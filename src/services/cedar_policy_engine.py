"""
Cedar Policy Engine Integration for Cross-Zone Consistency Rules.

This module provides integration with AWS Cedar policy language for defining
and evaluating document validation rules. It supports hot-reload of policies
and versioned rule management.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import yaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Note: cedar-policy Python bindings would be imported here
# For now, we'll implement a compatible interface
try:
    # This would be the actual Cedar policy engine
    # import cedar_policy as cedar
    pass
except ImportError:
    # Fallback implementation for development
    pass

from src.marty_common.observability import MetricsCollector, StructuredLogger


@dataclass
class ValidationContext:
    """Context for policy evaluation."""

    source_zone: str
    target_zone: str
    field_name: str
    source_value: str
    target_value: str
    document_type: str
    issuing_country: str
    extraction_confidence: float
    strict_mode: bool = False
    fuzzy_threshold: float | None = None
    tolerance: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyEvaluationResult:
    """Result of policy evaluation."""

    policy_id: str
    decision: str  # "Allow" or "Deny"
    reason: str
    confidence: float
    diagnostics: list[str] = field(default_factory=list)
    execution_time_ms: float = 0.0


@dataclass
class RulePack:
    """Container for a complete rule pack."""

    metadata: dict[str, Any]
    field_mappings: dict[str, dict[str, Any]]
    validation_rules: list[dict[str, Any]]
    cedar_policies: list[dict[str, Any]]
    global_settings: dict[str, Any] = field(default_factory=dict)
    loaded_at: datetime = field(default_factory=datetime.now)
    file_path: str | None = None


class RulePackWatcher(FileSystemEventHandler):
    """File system watcher for hot-reloading rule packs."""

    def __init__(self, engine: CedarPolicyEngine):
        self.engine = engine
        self.logger = StructuredLogger(__name__)

    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return

        file_path = Path(event.src_path)
        if file_path.suffix in {".yaml", ".yml", ".json"}:
            self.logger.info(f"Rule pack file modified: {file_path}")
            asyncio.create_task(self.engine.reload_rule_pack(str(file_path)))


class CedarPolicyEngine:
    """
    Cedar Policy Engine for Cross-Zone Consistency Rules.

    This engine loads and evaluates Cedar policies for document validation,
    supporting hot-reload and versioned rule management.
    """

    def __init__(self, rule_packs_dir: str = "config/rules"):
        """Initialize the Cedar policy engine."""
        self.logger = StructuredLogger(__name__)
        self.metrics = MetricsCollector("cedar_policy_engine")

        self.rule_packs_dir = Path(rule_packs_dir)
        self.rule_packs: dict[str, RulePack] = {}
        self.active_policies: dict[str, Any] = {}
        self.schema_cache: dict[str, Any] = {}

        # File watcher for hot-reload
        self.observer: Observer | None = None
        self.watcher_enabled = True

        # Cedar engine instance (placeholder for actual implementation)
        self.cedar_engine = None

        self.logger.info(
            "Cedar Policy Engine initialized", extra={"rule_packs_dir": str(self.rule_packs_dir)}
        )

    async def initialize(self) -> None:
        """Initialize the policy engine and load rule packs."""
        try:
            # Load Cedar schema
            await self._load_cedar_schema()

            # Load all rule packs
            await self._load_all_rule_packs()

            # Start file watcher if enabled
            if self.watcher_enabled:
                await self._start_file_watcher()

            self.metrics.increment("engine_initialized")
            self.logger.info(
                "Cedar Policy Engine initialized successfully",
                extra={
                    "rule_packs_loaded": len(self.rule_packs),
                    "active_policies": len(self.active_policies),
                },
            )

        except Exception as e:
            self.logger.error(f"Failed to initialize Cedar Policy Engine: {e}", exc_info=True)
            self.metrics.increment("engine_initialization_errors")
            raise

    async def _load_cedar_schema(self) -> None:
        """Load the Cedar schema definition."""
        schema_path = self.rule_packs_dir.parent / "cedar_schema.cedarschema"

        if schema_path.exists():
            try:
                with open(schema_path) as f:
                    schema_content = json.load(f)

                # In a real implementation, this would validate against Cedar schema
                self.schema_cache["main"] = schema_content
                self.logger.info("Cedar schema loaded successfully")

            except Exception as e:
                self.logger.error(f"Failed to load Cedar schema: {e}")
                raise
        else:
            self.logger.warning(f"Cedar schema not found at {schema_path}")

    async def _load_all_rule_packs(self) -> None:
        """Load all rule packs from the rules directory."""
        if not self.rule_packs_dir.exists():
            self.rule_packs_dir.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Created rule packs directory: {self.rule_packs_dir}")
            return

        for file_path in self.rule_packs_dir.glob("*.yaml"):
            try:
                await self.load_rule_pack(str(file_path))
            except Exception as e:
                self.logger.error(f"Failed to load rule pack {file_path}: {e}")
                self.metrics.increment("rule_pack_load_errors")

    async def load_rule_pack(self, file_path: str) -> str:
        """
        Load a rule pack from a YAML file.

        Args:
            file_path: Path to the rule pack file

        Returns:
            Rule pack identifier
        """
        start_time = time.time()

        try:
            with open(file_path) as f:
                rule_pack_data = yaml.safe_load(f)

            # Validate rule pack structure
            await self._validate_rule_pack(rule_pack_data)

            # Create rule pack object
            rule_pack = RulePack(
                metadata=rule_pack_data.get("metadata", {}),
                field_mappings=rule_pack_data.get("field_mappings", {}),
                validation_rules=rule_pack_data.get("validation_rules", []),
                cedar_policies=rule_pack_data.get("cedar_policies", []),
                global_settings=rule_pack_data.get("global_settings", {}),
                file_path=file_path,
            )

            # Generate rule pack ID
            pack_id = rule_pack.metadata.get("name", Path(file_path).stem)

            # Load Cedar policies
            await self._load_cedar_policies(rule_pack, pack_id)

            # Store rule pack
            self.rule_packs[pack_id] = rule_pack

            load_time = (time.time() - start_time) * 1000
            self.metrics.histogram("rule_pack_load_time_ms", load_time)
            self.metrics.increment("rule_packs_loaded")

            self.logger.info(
                "Rule pack loaded successfully",
                extra={
                    "pack_id": pack_id,
                    "file_path": file_path,
                    "policies_count": len(rule_pack.cedar_policies),
                    "load_time_ms": load_time,
                },
            )

            return pack_id

        except Exception as e:
            self.logger.error(f"Failed to load rule pack from {file_path}: {e}", exc_info=True)
            self.metrics.increment("rule_pack_load_errors")
            raise

    async def reload_rule_pack(self, file_path: str) -> None:
        """Reload a rule pack from file."""
        try:
            pack_id = await self.load_rule_pack(file_path)
            self.metrics.increment("rule_packs_reloaded")
            self.logger.info(f"Rule pack reloaded: {pack_id}")
        except Exception as e:
            self.logger.error(f"Failed to reload rule pack {file_path}: {e}")
            self.metrics.increment("rule_pack_reload_errors")

    async def _validate_rule_pack(self, rule_pack_data: dict[str, Any]) -> None:
        """Validate rule pack structure against schema."""
        required_fields = ["metadata", "field_mappings", "validation_rules", "cedar_policies"]

        for field in required_fields:
            if field not in rule_pack_data:
                raise ValueError(f"Missing required field: {field}")

        # Validate metadata
        metadata = rule_pack_data["metadata"]
        if "name" not in metadata or "version" not in metadata:
            raise ValueError("Rule pack metadata must include name and version")

        # Additional validation would go here

    async def _load_cedar_policies(self, rule_pack: RulePack, pack_id: str) -> None:
        """Load Cedar policies from rule pack."""
        for policy_data in rule_pack.cedar_policies:
            policy_id = f"{pack_id}::{policy_data['policy_id']}"

            # In a real implementation, this would compile Cedar policies
            # For now, we store the policy data
            self.active_policies[policy_id] = {
                "pack_id": pack_id,
                "policy_data": policy_data,
                "compiled_policy": None,  # Would be actual Cedar policy object
            }

    async def evaluate_validation_rule(
        self, rule_id: str, context: ValidationContext
    ) -> PolicyEvaluationResult:
        """
        Evaluate a validation rule using Cedar policies.

        Args:
            rule_id: Identifier of the rule to evaluate
            context: Validation context

        Returns:
            Policy evaluation result
        """
        start_time = time.time()

        try:
            # Find matching policies
            matching_policies = self._find_policies_for_rule(rule_id)

            if not matching_policies:
                return PolicyEvaluationResult(
                    policy_id=rule_id,
                    decision="Allow",  # Default to allow if no policies match
                    reason="No matching policies found",
                    confidence=0.5,
                )

            # Evaluate policies (placeholder implementation)
            result = await self._evaluate_policies(matching_policies, context)

            execution_time = (time.time() - start_time) * 1000
            result.execution_time_ms = execution_time

            self.metrics.histogram("policy_evaluation_time_ms", execution_time)
            self.metrics.increment("policies_evaluated")

            return result

        except Exception as e:
            self.logger.error(f"Policy evaluation failed for rule {rule_id}: {e}", exc_info=True)
            self.metrics.increment("policy_evaluation_errors")

            return PolicyEvaluationResult(
                policy_id=rule_id,
                decision="Deny",
                reason=f"Evaluation error: {str(e)}",
                confidence=0.0,
                diagnostics=[str(e)],
            )

    def _find_policies_for_rule(self, rule_id: str) -> list[str]:
        """Find Cedar policies that apply to a given rule."""
        matching_policies = []

        for policy_id, policy_info in self.active_policies.items():
            policy_data = policy_info["policy_data"]

            # Simple matching logic - in practice this would be more sophisticated
            if rule_id in policy_data.get("annotations", {}).get("rule_id", ""):
                matching_policies.append(policy_id)

        return matching_policies

    async def _evaluate_policies(
        self, policy_ids: list[str], context: ValidationContext
    ) -> PolicyEvaluationResult:
        """Evaluate a set of policies against the validation context."""

        # This is a placeholder implementation
        # In practice, this would use the actual Cedar policy engine

        # Create Cedar entities and context
        entities = self._create_cedar_entities(context)
        request = self._create_cedar_request(context)

        # Evaluate policies (simulated)
        decisions = []
        diagnostics = []

        for policy_id in policy_ids:
            policy_info = self.active_policies[policy_id]
            policy_data = policy_info["policy_data"]

            # Simulate policy evaluation
            decision = self._simulate_policy_evaluation(policy_data, context)
            decisions.append(decision)
            diagnostics.append(f"Policy {policy_id}: {decision['effect']}")

        # Combine decisions (Deny takes precedence)
        final_decision = "Allow"
        if any(d["effect"] == "Deny" for d in decisions):
            final_decision = "Deny"

        # Calculate confidence based on matching criteria
        confidence = self._calculate_policy_confidence(context, decisions)

        return PolicyEvaluationResult(
            policy_id=policy_ids[0] if policy_ids else "unknown",
            decision=final_decision,
            reason=f"Evaluated {len(policy_ids)} policies",
            confidence=confidence,
            diagnostics=diagnostics,
        )

    def _create_cedar_entities(self, context: ValidationContext) -> dict[str, Any]:
        """Create Cedar entities from validation context."""
        return {
            "source_zone": {
                "type": "DocumentZone",
                "attrs": {
                    "zone_type": context.source_zone,
                    "extraction_confidence": int(context.extraction_confidence * 100),
                    "extraction_method": "ocr",  # Would be dynamic
                    "metadata": set(),
                },
            },
            "target_zone": {
                "type": "DocumentZone",
                "attrs": {
                    "zone_type": context.target_zone,
                    "extraction_confidence": int(context.extraction_confidence * 100),
                    "extraction_method": "ocr",  # Would be dynamic
                    "metadata": set(),
                },
            },
            "field": {
                "type": "DocumentField",
                "attrs": {
                    "canonical_name": context.field_name,
                    "data_type": "string",  # Would be determined from field mappings
                    "is_required": True,
                },
            },
            "comparison_context": {
                "type": "ComparisonContext",
                "attrs": {
                    "source_value": context.source_value,
                    "target_value": context.target_value,
                    "strict_mode": context.strict_mode,
                    "fuzzy_threshold": int((context.fuzzy_threshold or 0.8) * 100),
                    "tolerance": int((context.tolerance or 0.0) * 100),
                },
            },
        }

    def _create_cedar_request(self, context: ValidationContext) -> dict[str, Any]:
        """Create Cedar authorization request."""
        return {
            "principal": 'ValidationRule::"FIELD_EXACT_MATCH"',  # Would be dynamic
            "action": "ValidateFieldConsistency",
            "resource": 'ComparisonContext::"validation_context"',
        }

    def _simulate_policy_evaluation(
        self, policy_data: dict[str, Any], context: ValidationContext
    ) -> dict[str, Any]:
        """Simulate Cedar policy evaluation (placeholder)."""

        # Simple rule-based evaluation
        if policy_data.get("effect") == "forbid":
            # Check conditions
            if context.source_value != context.target_value:
                return {"effect": "Deny", "reason": "Values do not match"}

        return {"effect": "Allow", "reason": "Policy conditions satisfied"}

    def _calculate_policy_confidence(
        self, context: ValidationContext, decisions: list[dict[str, Any]]
    ) -> float:
        """Calculate confidence score for policy decisions."""

        # Base confidence on extraction confidence and decision unanimity
        base_confidence = context.extraction_confidence

        if decisions:
            # Check if all decisions agree
            effects = [d["effect"] for d in decisions]
            if len(set(effects)) == 1:  # All decisions agree
                return min(base_confidence + 0.1, 1.0)
            else:  # Mixed decisions
                return base_confidence * 0.8

        return base_confidence

    async def _start_file_watcher(self) -> None:
        """Start file system watcher for hot-reload."""
        if self.observer is None:
            self.observer = Observer()
            event_handler = RulePackWatcher(self)
            self.observer.schedule(event_handler, str(self.rule_packs_dir), recursive=False)
            self.observer.start()
            self.logger.info("File watcher started for hot-reload")

    async def stop(self) -> None:
        """Stop the policy engine and cleanup resources."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None

        self.logger.info("Cedar Policy Engine stopped")

    def get_rule_pack_info(self, pack_id: str | None = None) -> dict[str, Any]:
        """Get information about loaded rule packs."""
        if pack_id:
            if pack_id in self.rule_packs:
                pack = self.rule_packs[pack_id]
                return {
                    "metadata": pack.metadata,
                    "policies_count": len(pack.cedar_policies),
                    "rules_count": len(pack.validation_rules),
                    "loaded_at": pack.loaded_at.isoformat(),
                    "file_path": pack.file_path,
                }
            else:
                return {}
        else:
            return {
                pack_id: {
                    "metadata": pack.metadata,
                    "policies_count": len(pack.cedar_policies),
                    "rules_count": len(pack.validation_rules),
                    "loaded_at": pack.loaded_at.isoformat(),
                }
                for pack_id, pack in self.rule_packs.items()
            }

    def get_active_policies_count(self) -> int:
        """Get count of active policies."""
        return len(self.active_policies)

    def set_validation_mode(self, mode: str) -> None:
        """Set global validation mode (strict/lenient)."""
        # This would update policy evaluation behavior
        self.logger.info(f"Validation mode set to: {mode}")
