# Enhanced Trust Service Integration Test

This enhanced integration test provides comprehensive testing of the trust service with both synthetic and real master list files, using mocked PKD service components to enable testing without external dependencies.

## Usage

### Basic Synthetic Testing (Default)
Test with generated synthetic master lists only:
```bash
python3 tests/integration/test_enhanced_trust_service.py
```

### Testing with Real Master Lists
Test with real master list files from a specific directory:
```bash
python3 tests/integration/test_enhanced_trust_service.py --real-ml-path /path/to/masterlist/directory
```

**Important**: Real master list files are **read directly** from the source path - **no copies are made**.

### Examples

#### Test with project's existing master lists:
```bash
# Test with ASN.1 formatted master lists
python3 tests/integration/test_enhanced_trust_service.py --real-ml-path data/final_asn1_test

# Test with other format master lists  
python3 tests/integration/test_enhanced_trust_service.py --real-ml-path data/ml_test_new
```

#### Synthetic testing only:
```bash
python3 tests/integration/test_enhanced_trust_service.py --synthetic-only
```

## What the Test Does

### Synthetic Master List Testing
1. **🧪 Master List Generation**: Creates synthetic master lists for multiple countries
2. **🔍 ASN.1 Parsing**: Tests parsing with mocked ASN.1 decoder  
3. **🔒 Trust Service Validation**: Validates master lists through mocked trust service
4. **📤 Upload Simulation**: Simulates master list upload workflow
5. **🎯 End-to-End Workflow**: Complete pipeline validation

### Real Master List Testing (when `--real-ml-path` provided)
1. **📁 File Discovery**: Finds all `.ml` files in the specified directory
2. **📄 Format Validation**: Checks if files start with ASN.1 SEQUENCE tag (`0x30`)
3. **🔍 Certificate Parsing**: Extracts certificates using mocked ASN.1 decoder
4. **🔒 Trust Validation**: Validates real files through mocked trust service
5. **📊 Results Summary**: Reports processing statistics

## Key Features

### ✅ **No File Copying**
- Real master list files are read directly from source
- No temporary copies or modifications made
- Original files remain untouched

### ✅ **Comprehensive Testing**
- Tests both synthetic and real master lists
- Validates complete trust service workflow
- Provides detailed logging and reporting

### ✅ **Mocked Dependencies**
- Works without real PKD service components
- Fast execution with consistent results
- No external service dependencies

## Test Results

The test provides comprehensive reporting including:

- **📄 .ML Files Created**: Number of synthetic files generated
- **📋 Real ML Files Found**: Number of real files discovered
- **📜 Certificates Processed**: Total certificates from all sources
- **🔒 Validations Completed**: Successful trust service validations
- **🎯 Overall Result**: Pass/fail status with detailed breakdown

## Exit Codes

- `0`: All tests passed successfully
- `1`: One or more tests failed

## Security Notes

- Real master list files are **never copied or modified**
- Only read access is required to the source directory
- Test artifacts are isolated in temporary directories
- No sensitive data is logged or persisted

## Example Output

```
🔒 Enhanced Trust Service Integration Test
Testing synthetic master list generation and processing with mocked PKD service
Additionally testing real master lists from: data/final_asn1_test

📊 Test Results:
   🧪 Master List Generation: ✅ PASS
   🔍 ASN.1 Parsing (Mocked): ✅ PASS  
   🔒 Trust Service Validation: ✅ PASS
   📤 Upload Simulation: ✅ PASS
   🧪 Real Master List Testing: ✅ PASS

🎯 OVERALL RESULT: ✅ SUCCESS
✅ Real master list files processed successfully!
📝 NOTE: Real master list files were read directly from source - no copies made.
```