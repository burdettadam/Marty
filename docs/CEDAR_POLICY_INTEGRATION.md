# Cross-Zone Consistency Engine: Cedar Policy Integration

## Overview

The Cross-Zone Consistency Engine now supports **AWS Cedar** policy language for defining document validation rules. This extensible, versioned ruleset library provides:

- 🌲 **Cedar Policy Language** integration for flexible rule definition
- 🔄 **Hot-reload** capabilities for runtime rule updates
- 📦 **Versioned rule packs** for different document types and regions
- 🔒 **Strict/Lenient/Adaptive** validation modes
- 🎯 **High-performance** policy evaluation with caching

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Consistency Engine                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐    ┌─────────────────────────────────┐ │
│  │   gRPC/REST     │    │      Cedar Policy Engine        │ │
│  │   API Layer     │◄──►│   - Rule Pack Management        │ │
│  │                 │    │   - Policy Evaluation           │ │
│  └─────────────────┘    │   - Hot-reload Support          │ │
│                         └─────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Rule Pack Storage                       │
│  ┌─────────────────┐ ┌─────────────────┐ ┌───────────────┐ │
│  │   Passport      │ │ Driver License  │ │  National ID  │ │
│  │   Rules         │ │   Rules         │ │    Rules      │ │
│  │   (YAML)        │ │   (YAML)        │ │   (YAML)      │ │
│  └─────────────────┘ └─────────────────┘ └───────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Cedar Policy Schema

The Cedar schema defines entities and actions for document validation:

### Entities

- **DocumentZone**: Represents extraction zones (VISUAL_OCR, MRZ, BARCODE, RFID)
- **DocumentField**: Canonical document fields with validation rules
- **DocumentType**: Document type definitions with supported zones
- **ValidationRule**: Individual validation rules with parameters
- **ComparisonContext**: Context for field comparisons between zones

### Actions

- **ValidateFieldConsistency**: Check field consistency between zones
- **CheckCrossZoneMatch**: Perform cross-zone matching
- **ValidateChecksum**: Validate checksum fields
- **ValidateDateFormat**: Validate date format consistency
- **ValidateHashValue**: Validate hash-based fields
- **ApplyStrictMode**: Apply strict validation rules
- **ApplyLenientMode**: Apply lenient validation rules

## Rule Pack Format

Rule packs are defined in YAML format with the following structure:

```yaml
metadata:
  name: "Document Validation Rules"
  version: "1.0.0"
  document_types: [passport, drivers_license]
  validation_mode: strict
  issuing_countries: ["USA", "CAN", "GBR"]
  tags: ["government_issued", "machine_readable"]

field_mappings:
  DOCUMENT_NUMBER:
    canonical_field: "DOCUMENT_NUMBER"
    zone_mappings:
      VISUAL_OCR: "document_number"
      MRZ: "document_number"
      RFID_CHIP: "document_number"
    data_type: string
    validation_regex: "^[A-Z0-9]{6,12}$"
    is_required: true

validation_rules:
  - rule_id: "EXACT_MATCH"
    name: "Field Exact Match"
    rule_type: exact_match
    applicable_fields: ["DOCUMENT_NUMBER"]
    sources: ["VISUAL_OCR", "MRZ"]
    targets: ["VISUAL_OCR", "MRZ"]
    severity: critical
    confidence_threshold: 0.95

cedar_policies:
  - policy_id: "exact_match_policy"
    effect: permit
    principal: 'ValidationRule::"EXACT_MATCH"'
    action: 'ValidateFieldConsistency'
    resource: 'ComparisonContext'
    conditions:
      - condition: 'resource.source_value == resource.target_value'
```

## Validation Modes

### Strict Mode
- Higher confidence thresholds
- Exact matching preferred
- Lower tolerance for variations
- Used for high-security documents

### Lenient Mode
- Lower confidence thresholds
- Fuzzy matching with higher tolerance
- Accommodates OCR variations
- Used for damaged or low-quality documents

### Adaptive Mode
- Dynamic thresholds based on extraction confidence
- Automatically adjusts based on document quality
- Balances accuracy with usability

## API Usage

### Loading Rule Packs

```python
# Load a rule pack
request = LoadRulePackRequest()
request.file_path = "config/rules/passport_rules.yaml"
response = await consistency_engine.LoadRulePack(request, context)

# Reload existing rule pack
reload_request = ReloadRulePackRequest()
reload_request.pack_id = "passport_rules"
await consistency_engine.ReloadRulePack(reload_request, context)
```

### Setting Validation Mode

```python
# Set global validation mode
mode_request = SetValidationModeRequest()
mode_request.mode = ValidationMode.STRICT
await consistency_engine.SetValidationMode(mode_request, context)
```

### Evaluating Cedar Policies

```python
# Evaluate specific policy
eval_request = EvaluateCedarPolicyRequest()
eval_request.rule_id = "PASSPORT_EXACT_MATCH"
eval_request.context.source_zone = "VISUAL_OCR"
eval_request.context.target_zone = "MRZ"
eval_request.context.field_name = "DOCUMENT_NUMBER"
eval_request.context.source_value = "A1234567"
eval_request.context.target_value = "A1234567"

response = await consistency_engine.EvaluateCedarPolicy(eval_request, context)
```

## Hot-Reload Support

The Cedar Policy Engine monitors rule pack files for changes and automatically reloads them:

```python
# Enable hot-reload (enabled by default)
cedar_engine = CedarPolicyEngine("config/rules")
await cedar_engine.initialize()

# File system watcher automatically detects changes
# Rule packs are reloaded without service restart
```

## Sample Rule Packs

### Passport Rules (`passport_rules.yaml`)
- Strict validation for passport documents
- MRZ checksum validation
- High confidence thresholds
- Exact matching for critical fields

### Driver's License Rules (`drivers_license_rules.yaml`)
- Lenient validation by default
- Barcode data prioritization
- Address fuzzy matching
- State/province validation

### National ID Rules (`national_id_rules.yaml`)
- RFID chip hash validation
- Strict name matching
- Multi-format date support
- Cross-reference validation

## Performance Considerations

- **Policy Caching**: Compiled Cedar policies are cached in memory
- **Concurrent Evaluation**: Multiple policies can be evaluated in parallel
- **Timeout Protection**: Policy evaluation includes timeout protection
- **Metrics Collection**: Comprehensive metrics for monitoring performance

## Error Handling

The system includes robust error handling:

- **Rule Pack Validation**: Schema validation before loading
- **Policy Compilation**: Cedar policy syntax validation
- **Fallback Mechanisms**: Traditional rules as fallback for Cedar failures
- **Audit Trail**: Complete audit trail for troubleshooting

## Configuration

### Global Settings

```yaml
global_settings:
  default_fuzzy_threshold: 0.85
  default_confidence_threshold: 0.9
  enable_hot_reload: true
  cache_policies: true
  policy_evaluation_timeout_ms: 5000
```

### Environment Variables

```bash
# Rule packs directory
CEDAR_RULE_PACKS_DIR=config/rules

# Default validation mode
CEDAR_DEFAULT_MODE=strict

# Enable debug logging
CEDAR_DEBUG=true
```

## Monitoring and Observability

The Cedar Policy Engine includes comprehensive observability:

### Metrics
- `cedar_policies_evaluated_total`
- `cedar_policy_evaluation_duration_ms`
- `cedar_rule_packs_loaded_total`
- `cedar_rule_pack_load_errors_total`
- `cedar_hot_reload_events_total`

### Logging
- Structured JSON logging
- Policy evaluation traces
- Rule pack load/reload events
- Performance metrics

### Health Checks
- Rule pack validation status
- Cedar engine health
- Policy compilation status
- Hot-reload functionality

## Migration Guide

### From Traditional Rules

1. **Extract existing rules** into YAML format
2. **Define Cedar policies** for complex validation logic
3. **Test rule packs** in development environment
4. **Deploy incrementally** with feature flags
5. **Monitor performance** and adjust thresholds

### Backward Compatibility

The system maintains backward compatibility:
- Existing rules continue to work as fallback
- Gradual migration supported
- Feature flags for Cedar evaluation
- A/B testing capabilities

## Future Enhancements

- **Visual Rule Builder**: GUI for creating Cedar policies
- **Rule Testing Framework**: Automated testing for rule packs
- **Advanced Analytics**: ML-powered rule optimization
- **Cloud Integration**: Integration with AWS Cedar service
- **Real-time Monitoring**: Live rule performance dashboard

## Troubleshooting

### Common Issues

1. **Rule Pack Not Loading**
   - Check YAML syntax
   - Validate schema compliance
   - Check file permissions

2. **Policy Evaluation Errors**
   - Verify Cedar syntax
   - Check entity definitions
   - Review condition logic

3. **Hot-Reload Not Working**
   - Check file system permissions
   - Verify watch directory
   - Review log files

### Debug Mode

Enable debug logging for detailed information:

```python
import logging
logging.getLogger('cedar_policy_engine').setLevel(logging.DEBUG)
```

---

## Quick Start

1. **Install dependencies**:
   ```bash
   pip install -r requirements_cedar.txt
   ```

2. **Initialize Cedar engine**:
   ```python
   from src.services.cedar_policy_engine import CedarPolicyEngine
   
   engine = CedarPolicyEngine("config/rules")
   await engine.initialize()
   ```

3. **Load rule pack**:
   ```python
   pack_id = await engine.load_rule_pack("config/rules/passport_rules.yaml")
   ```

4. **Evaluate policy**:
   ```python
   context = ValidationContext(...)
   result = await engine.evaluate_validation_rule("PASSPORT_EXACT_MATCH", context)
   ```

5. **Run demo**:
   ```bash
   python examples/cedar_policy_demo.py
   ```

For more examples and detailed API documentation, see the `examples/` directory and inline code documentation.