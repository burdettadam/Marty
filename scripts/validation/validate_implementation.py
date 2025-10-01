#!/usr/bin/env python3
"""
Comprehensive Feature Validation Script

This script validates the implementation status of the passport verification system
by checking for required modules, classes, functions, and integration points.
"""

import os
import sys
import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import Optional, Any
import json


class FeatureValidator:
    """Validates implementation completeness of passport verification features."""
    
    def __init__(self, src_path: str = "src"):
        self.src_path = Path(src_path)
        self.results = {
            "phase_1_core_crypto": {},
            "phase_2_rfid_testing": {},
            "phase_3_advanced_security": {},
            "phase_4_production": {},
            "integration_status": {},
            "missing_features": [],
            "quality_metrics": {}
        }
        
        # Add src to Python path
        sys.path.insert(0, str(self.src_path.parent))
        
    def validate_module_exists(self, module_path: str) -> bool:
        """Check if a module exists and can be imported."""
        try:
            spec = importlib.util.find_spec(module_path)
            return spec is not None
        except (ImportError, ValueError, ModuleNotFoundError):
            return False
            
    def validate_class_exists(self, module_path: str, class_name: str) -> bool:
        """Check if a class exists in the specified module."""
        try:
            module = importlib.import_module(module_path)
            return hasattr(module, class_name)
        except (ImportError, AttributeError, ModuleNotFoundError):
            return False
            
    def validate_function_exists(self, module_path: str, function_name: str) -> bool:
        """Check if a function exists in the specified module."""
        try:
            module = importlib.import_module(module_path)
            attr = getattr(module, function_name, None)
            return callable(attr)
        except (ImportError, AttributeError, ModuleNotFoundError):
            return False
            
    def get_module_methods(self, module_path: str, class_name: str) -> list[str]:
        """Get all methods of a class in a module."""
        try:
            module = importlib.import_module(module_path)
            cls = getattr(module, class_name)
            return [name for name, method in inspect.getmembers(cls, predicate=inspect.ismethod) 
                   if not name.startswith('_')]
        except:
            return []
            
    def validate_phase_1_crypto(self):
        """Validate Phase 1: Core Cryptographic Verification."""
        print("🔍 Validating Phase 1: Core Cryptographic Verification...")
        
        features = {
            "sod_parser": {
                "module": "src.marty_common.crypto.sod_parser",
                "classes": ["SODParser", "LDSSecurityObject"],
                "functions": ["parse_sod", "extract_data_group_hashes"]
            },
            "data_group_hasher": {
                "module": "src.marty_common.crypto.data_group_hasher", 
                "classes": ["DataGroupHasher", "DataGroupHashResult"],
                "functions": ["compute_hash", "compute_data_group_hash"]
            },
            "hash_comparison": {
                "module": "src.marty_common.crypto.hash_comparison",
                "classes": ["HashComparisonEngine", "IntegrityVerificationReport"],
                "functions": ["compare_hashes", "verify_integrity"]
            },
            "certificate_validator": {
                "module": "src.marty_common.crypto.certificate_validator",
                "classes": ["CertificateChainValidator", "ValidationResult"],
                "functions": ["validate_certificate_chain", "verify_signature"]
            }
        }
        
        for feature_name, spec in features.items():
            result = {
                "module_exists": self.validate_module_exists(spec["module"]),
                "classes_found": [],
                "functions_found": [],
                "completion_score": 0
            }
            
            if result["module_exists"]:
                for class_name in spec.get("classes", []):
                    if self.validate_class_exists(spec["module"], class_name):
                        result["classes_found"].append(class_name)
                        
                for func_name in spec.get("functions", []):
                    if self.validate_function_exists(spec["module"], func_name):
                        result["functions_found"].append(func_name)
                        
                total_features = len(spec.get("classes", [])) + len(spec.get("functions", []))
                found_features = len(result["classes_found"]) + len(result["functions_found"])
                result["completion_score"] = (found_features / total_features * 100) if total_features > 0 else 0
                
            self.results["phase_1_core_crypto"][feature_name] = result
            print(f"  ✅ {feature_name}: {result['completion_score']:.1f}% complete")
            
    def validate_phase_2_rfid(self):
        """Validate Phase 2: RFID Testing Infrastructure."""
        print("🔍 Validating Phase 2: RFID Testing Infrastructure...")
        
        features = {
            "rfid_protocols": {
                "module": "src.marty_common.rfid.nfc_protocols",
                "classes": ["NFCProtocolHandler", "RFIDInterface"],
                "functions": ["establish_connection", "read_data_groups"]
            },
            "passport_apdu": {
                "module": "src.marty_common.rfid.passport_apdu",
                "classes": ["PassportAPDU", "APDUCommand"],
                "functions": ["select_elementary_file", "read_binary"]
            },
            "elementary_files": {
                "module": "src.marty_common.rfid.elementary_files",
                "classes": ["ElementaryFileParser", "DataGroup"],
                "functions": ["parse_dg1_mrz", "parse_dg2_biometric"]
            },
            "secure_messaging": {
                "module": "src.marty_common.rfid.secure_messaging",
                "classes": ["SecureMessaging", "SessionKeys"],
                "functions": ["establish_secure_channel", "encrypt_command"]
            }
        }
        
        for feature_name, spec in features.items():
            result = {
                "module_exists": self.validate_module_exists(spec["module"]),
                "classes_found": [],
                "functions_found": [],
                "completion_score": 0
            }
            
            if result["module_exists"]:
                for class_name in spec.get("classes", []):
                    if self.validate_class_exists(spec["module"], class_name):
                        result["classes_found"].append(class_name)
                        
                for func_name in spec.get("functions", []):
                    if self.validate_function_exists(spec["module"], func_name):
                        result["functions_found"].append(func_name)
                        
                total_features = len(spec.get("classes", [])) + len(spec.get("functions", []))
                found_features = len(result["classes_found"]) + len(result["functions_found"])
                result["completion_score"] = (found_features / total_features * 100) if total_features > 0 else 0
            else:
                print(f"  ❌ {feature_name}: Module not found")
                
            self.results["phase_2_rfid_testing"][feature_name] = result
            
    def validate_phase_3_security(self):
        """Validate Phase 3: Advanced Security Features."""
        print("🔍 Validating Phase 3: Advanced Security Features...")
        
        features = {
            "eac_protocol": {
                "module": "src.marty_common.crypto.eac_protocol",
                "classes": ["EACProtocolHandler", "TerminalCertificate"],
                "functions": ["perform_terminal_authentication", "perform_chip_authentication"]
            },
            "active_authentication": {
                "module": "src.marty_common.security.active_authentication",
                "classes": ["ActiveAuthEngine", "ChallengeResponse"],
                "functions": ["generate_challenge", "verify_response"]
            },
            "biometric_processing": {
                "module": "src.marty_common.security.enhanced_biometric_processing",
                "classes": ["BiometricProcessor", "FaceRecognition"],
                "functions": ["process_facial_image", "extract_features"]
            },
            "csca_trust_store": {
                "module": "src.marty_common.crypto.csca_trust_store",
                "classes": ["CSCATrustStore", "TrustAnchor"],
                "functions": ["verify_csca_certificate", "load_trust_anchors"]
            }
        }
        
        for feature_name, spec in features.items():
            result = {
                "module_exists": self.validate_module_exists(spec["module"]),
                "classes_found": [],
                "functions_found": [],
                "completion_score": 0
            }
            
            if result["module_exists"]:
                for class_name in spec.get("classes", []):
                    if self.validate_class_exists(spec["module"], class_name):
                        result["classes_found"].append(class_name)
                        
                for func_name in spec.get("functions", []):
                    if self.validate_function_exists(spec["module"], func_name):
                        result["functions_found"].append(func_name)
                        
                total_features = len(spec.get("classes", [])) + len(spec.get("functions", []))
                found_features = len(result["classes_found"]) + len(result["functions_found"])
                result["completion_score"] = (found_features / total_features * 100) if total_features > 0 else 0
                
            self.results["phase_3_advanced_security"][feature_name] = result
            print(f"  ✅ {feature_name}: {result['completion_score']:.1f}% complete")
            
    def validate_phase_4_production(self):
        """Validate Phase 4: Production Integration Features."""
        print("🔍 Validating Phase 4: Production Integration Features...")
        
        features = {
            "pkd_integration": {
                "module": "src.pkd_service.simple_pkd_mirror",
                "classes": ["PKDMirror", "CertificateDownloader"],
                "functions": ["sync_certificates", "download_masterlist"]
            },
            "crl_validation": {
                "module": "src.marty_common.crypto.certificate_validator",
                "classes": ["CRLValidator", "OCSPValidator"], 
                "functions": ["check_revocation_status", "validate_crl"]
            },
            "hardware_integration": {
                "module": "src.marty_common.hardware.pcsc_reader",
                "classes": ["PCSCReader", "ReaderManager"],
                "functions": ["initialize_readers", "transmit_apdu"]
            },
            "monitoring": {
                "module": "src.marty_common.monitoring",
                "classes": ["SystemMonitor", "PerformanceMetrics"],
                "functions": ["collect_metrics", "generate_report"]
            }
        }
        
        for feature_name, spec in features.items():
            result = {
                "module_exists": self.validate_module_exists(spec["module"]),
                "classes_found": [],
                "functions_found": [],
                "completion_score": 0
            }
            
            if result["module_exists"]:
                for class_name in spec.get("classes", []):
                    if self.validate_class_exists(spec["module"], class_name):
                        result["classes_found"].append(class_name)
                        
                for func_name in spec.get("functions", []):
                    if self.validate_function_exists(spec["module"], func_name):
                        result["functions_found"].append(func_name)
                        
                total_features = len(spec.get("classes", [])) + len(spec.get("functions", []))
                found_features = len(result["classes_found"]) + len(result["functions_found"])
                result["completion_score"] = (found_features / total_features * 100) if total_features > 0 else 0
            else:
                print(f"  ❌ {feature_name}: Module not found")
                
            self.results["phase_4_production"][feature_name] = result
            
    def analyze_quality_metrics(self):
        """Analyze code quality metrics from reports."""
        print("🔍 Analyzing Code Quality Metrics...")
        
        # Parse Ruff report
        ruff_issues = 0
        if os.path.exists("ruff_report.json"):
            try:
                with open("ruff_report.json", "r") as f:
                    ruff_data = json.load(f)
                    ruff_issues = len(ruff_data) if isinstance(ruff_data, list) else 0
            except:
                ruff_issues = "unknown"
                
        # Parse MyPy report
        mypy_errors = 0
        if os.path.exists("mypy_report.txt"):
            try:
                with open("mypy_report.txt/index.txt", "r") as f:
                    content = f.read()
                    # Extract error count from MyPy output
                    if "Found" in content and "errors" in content:
                        import re
                        match = re.search(r"Found (\d+) errors", content)
                        if match:
                            mypy_errors = int(match.group(1))
            except:
                mypy_errors = "unknown"
                
        self.results["quality_metrics"] = {
            "ruff_issues": ruff_issues,
            "mypy_errors": mypy_errors,
            "code_quality_score": self._calculate_quality_score(ruff_issues, mypy_errors)
        }
        
    def _calculate_quality_score(self, ruff_issues, mypy_errors):
        """Calculate overall code quality score."""
        if isinstance(ruff_issues, str) or isinstance(mypy_errors, str):
            return "unknown"
            
        # Simple scoring: start at 100 and deduct points
        score = 100
        score -= min(ruff_issues * 0.1, 30)  # Max 30 point deduction for ruff issues
        score -= min(mypy_errors * 0.05, 50)  # Max 50 point deduction for type errors
        
        return max(0, round(score, 1))
        
    def identify_missing_features(self):
        """Identify critical missing features based on validation results."""
        print("🔍 Identifying Missing Features...")
        
        missing = []
        
        # Check each phase for incomplete features
        for phase_name, phase_results in self.results.items():
            if phase_name in ["phase_1_core_crypto", "phase_2_rfid_testing", 
                            "phase_3_advanced_security", "phase_4_production"]:
                for feature_name, feature_result in phase_results.items():
                    if isinstance(feature_result, dict):
                        if not feature_result.get("module_exists", False):
                            missing.append(f"{phase_name}: {feature_name} - Module missing")
                        elif feature_result.get("completion_score", 0) < 50:
                            missing.append(f"{phase_name}: {feature_name} - Incomplete implementation ({feature_result.get('completion_score', 0):.1f}%)")
                            
        self.results["missing_features"] = missing
        
    def generate_summary_report(self) -> str:
        """Generate a comprehensive summary report."""
        report = []
        report.append("=" * 80)
        report.append("PASSPORT VERIFICATION SYSTEM - IMPLEMENTATION STATUS REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Overall progress
        total_features = 0
        completed_features = 0
        
        for phase_name in ["phase_1_core_crypto", "phase_3_advanced_security"]:
            phase_results = self.results.get(phase_name, {})
            for feature_result in phase_results.values():
                if isinstance(feature_result, dict):
                    total_features += 1
                    if feature_result.get("completion_score", 0) >= 80:
                        completed_features += 1
                        
        overall_progress = (completed_features / total_features * 100) if total_features > 0 else 0
        
        report.append(f"📊 OVERALL PROGRESS: {overall_progress:.1f}% ({completed_features}/{total_features} features)")
        report.append("")
        
        # Phase summaries
        phase_names = {
            "phase_1_core_crypto": "Phase 1: Core Cryptographic Verification",
            "phase_2_rfid_testing": "Phase 2: RFID Testing Infrastructure", 
            "phase_3_advanced_security": "Phase 3: Advanced Security Features",
            "phase_4_production": "Phase 4: Production Integration"
        }
        
        for phase_key, phase_title in phase_names.items():
            report.append(f"📋 {phase_title}")
            report.append("-" * len(phase_title))
            
            phase_results = self.results.get(phase_key, {})
            if not phase_results:
                report.append("  ❌ No validation performed")
            else:
                for feature_name, feature_result in phase_results.items():
                    if isinstance(feature_result, dict):
                        score = feature_result.get("completion_score", 0)
                        status = "✅" if score >= 80 else "🔄" if score >= 50 else "❌"
                        report.append(f"  {status} {feature_name}: {score:.1f}%")
                        
                        if not feature_result.get("module_exists", False):
                            report.append(f"    • Module not found")
                        else:
                            classes_found = len(feature_result.get("classes_found", []))
                            functions_found = len(feature_result.get("functions_found", []))
                            if classes_found > 0:
                                report.append(f"    • Classes: {classes_found} found")
                            if functions_found > 0:
                                report.append(f"    • Functions: {functions_found} found")
                                
            report.append("")
            
        # Quality metrics
        quality = self.results.get("quality_metrics", {})
        report.append("🔍 CODE QUALITY METRICS")
        report.append("-" * 20)
        report.append(f"  • Ruff Issues: {quality.get('ruff_issues', 'unknown')}")
        report.append(f"  • MyPy Errors: {quality.get('mypy_errors', 'unknown')}")
        report.append(f"  • Quality Score: {quality.get('code_quality_score', 'unknown')}/100")
        report.append("")
        
        # Missing features
        missing = self.results.get("missing_features", [])
        if missing:
            report.append("⚠️  CRITICAL MISSING FEATURES")
            report.append("-" * 25)
            report.extend(f"  • {item}" for item in missing[:10])
            if len(missing) > 10:
                report.append(f"  ... and {len(missing) - 10} more")
        else:
            report.append("✅ No critical missing features identified")
            
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)
        
    def run_validation(self):
        """Run complete validation process."""
        print("🚀 Starting Passport Verification System Validation...")
        print("")
        
        try:
            self.validate_phase_1_crypto()
            self.validate_phase_2_rfid()
            self.validate_phase_3_security()
            self.validate_phase_4_production()
            self.analyze_quality_metrics()
            self.identify_missing_features()
            
            print("")
            print("✅ Validation completed successfully!")
            print("")
            
            # Generate and display summary
            summary = self.generate_summary_report()
            print(summary)
            
            # Save detailed results
            with open("validation_results.json", "w") as f:
                json.dump(self.results, f, indent=2)
                
            print("📄 Detailed results saved to validation_results.json")
            
        except Exception as e:
            print(f"❌ Validation failed: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    validator = FeatureValidator()
    validator.run_validation()