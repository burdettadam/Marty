"""
Data loaders for scraped test data.

This module provides utilities to load real data from scraped sources
for use in testing, providing higher confidence in implementation.
Falls back gracefully when scraped data is not available.
"""

from __future__ import annotations

import json
import logging
import secrets
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class TestDataLoader:
    """Loads scraped test data from various sources with graceful fallbacks."""
    
    def __init__(self, data_root: Path | None = None):
        """Initialize with data root directory."""
        if data_root is None:
            # Default to scraped data directory within tests
            self.data_root = Path(__file__).parents[1] / "scraped_data"
        else:
            self.data_root = Path(data_root)
        
        # Check if scraped data is available
        self.has_scraped_data = self.data_root.exists()
        if not self.has_scraped_data:
            logger.warning("Scraped data directory not found: %s", self.data_root)
    
    def _get_fallback_passport_data(self) -> dict[str, Any]:
        """Provide fallback passport data when scraped data is not available."""
        return {
            "passport_number": "P12345678",
            "issue_date": "2024-01-01",
            "expiry_date": "2034-01-01",
            "data_groups": {
                "DG1": "MRZ-DATA-FALLBACK",
                "DG2": "PHOTO-DATA-FALLBACK",
                "DG3": "FINGERPRINT-DATA-FALLBACK",
                "DG4": "IRIS-DATA-FALLBACK"
            },
            "sod": "FALLBACK_SOD_DATA",
            "_is_fallback": True
        }
    
    def _load_json_file(self, file_path: Path) -> dict[str, Any] | None:
        """Safely load a JSON file, returning None on error."""
        try:
            return json.loads(file_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.exception("Failed to load JSON file: %s", file_path)
            return None
    
    def _get_random_passport_file(self, passport_files: list[Path]) -> Path | None:
        """Select a random passport file using secure random."""
        if not passport_files:
            return None
        return passport_files[secrets.randbelow(len(passport_files))]
    
    def load_passport_data(self, passport_number: str | None = None) -> dict[str, Any]:
        """Load passport data from scraped files or fallback data."""
        fallback = self._get_fallback_passport_data()
        
        if not self.has_scraped_data:
            logger.info("Using fallback passport data - no scraped data available")
            return fallback
        
        passport_dir = self.data_root / "passport"
        
        if not passport_dir.exists():
            logger.warning("Passport data directory not found, using fallback")
            return fallback
        
        if passport_number:
            # Load specific passport
            passport_file = passport_dir / f"{passport_number}.json"
            if passport_file.exists():
                data = self._load_json_file(passport_file)
                return data if data is not None else fallback

            logger.warning("Passport data for %s not found, using fallback", passport_number)
            return fallback

        # Load random valid passport
        passport_files = [f for f in passport_dir.glob("*.json")
                        if not f.name.startswith("INVALID")]

        random_file = self._get_random_passport_file(passport_files)
        if random_file:
            data = self._load_json_file(random_file)
            return data if data is not None else fallback

        logger.warning("No valid passport data files found, using fallback")
        return fallback

    def load_all_passport_data(self) -> list[dict[str, Any]]:
        """Load all passport data files or return fallback data."""
        if not self.has_scraped_data:
            logger.info("Using fallback passport data collection")
            return [self._get_fallback_passport_data()]

        passport_dir = self.data_root / "passport"
        if not passport_dir.exists():
            logger.warning("Passport directory not found, using fallback")
            return [self._get_fallback_passport_data()]

        passport_data = []

        try:
            for passport_file in passport_dir.glob("*.json"):
                # Skip invalid passports unless specifically requested
                if passport_file.name.startswith("INVALID"):
                    continue

                data = self._load_json_file(passport_file)
                if data is not None:
                    data["_source_file"] = passport_file.name
                    passport_data.append(data)
        except OSError:
            logger.exception("Error scanning passport directory")

        if not passport_data:
            logger.warning("No passport data could be loaded, using fallback")
            return [self._get_fallback_passport_data()]

        return passport_data

    def load_invalid_passport_data(self) -> list[dict[str, Any]]:
        """Load invalid passport data for negative testing or return empty list."""
        if not self.has_scraped_data:
            logger.info("No scraped data available for invalid passports")
            return []

        passport_dir = self.data_root / "passport"
        if not passport_dir.exists():
            return []

        invalid_data = []

        try:
            for passport_file in passport_dir.glob("INVALID*.json"):
                data = self._load_json_file(passport_file)
                if data is not None:
                    data["_source_file"] = passport_file.name
                    invalid_data.append(data)
        except OSError:
            logger.exception("Error loading invalid passport data")

        return invalid_data

    def load_csca_lifecycle_data(self) -> dict[str, Any]:
        """Load CSCA certificate lifecycle event data or return fallback."""
        fallback_data = {
            "certificate_events": {
                "cert_fallback_001": [
                    {
                        "timestamp": "2024-01-01T00:00:00.000000+00:00",
                        "event_type": "created",
                        "days_remaining": 365
                    }
                ]
            },
            "_is_fallback": True
        }

        if not self.has_scraped_data:
            logger.info("Using fallback CSCA lifecycle data")
            return fallback_data

        csca_file = self.data_root / "csca" / "lifecycle_events.json"

        if csca_file.exists():
            data = self._load_json_file(csca_file)
            return data if data is not None else fallback_data

        logger.warning("CSCA lifecycle data not found, using fallback")
        return fallback_data

    def load_trust_store_data(self) -> dict[str, Any]:
        """Load trust store configuration data or return fallback."""
        fallback_data = {
            "trusted_entities": {
                "csca-service": True,
                "document-signer": True,
                "inspection-system": True,
                "passport-engine": True,
                "test-entity": True
            },
            "revoked_entities": [],
            "_is_fallback": True
        }

        if not self.has_scraped_data:
            logger.info("Using fallback trust store data")
            return fallback_data

        trust_file = self.data_root / "trust_store.json"

        if trust_file.exists():
            data = self._load_json_file(trust_file)
            return data if data is not None else fallback_data

        logger.warning("Trust store data not found, using fallback")
        return fallback_data

    def get_passport_by_type(self, passport_type: str) -> list[dict[str, Any]]:
        """Get passports by type (based on prefix) or return fallback data."""
        all_passports = self.load_all_passport_data()

        prefix_map = {
            "P": "P",      # Regular passports
            "IS": "IS",    # Iceland passports
            "PM": "PM"     # Special type
        }

        prefix = prefix_map.get(passport_type.upper(), passport_type)
        return [p for p in all_passports if p["passport_number"].startswith(prefix)]

    def get_sample_passports(self, count: int = 5) -> list[dict[str, Any]]:
        """Get a sample of passport data for testing."""
        all_passports = self.load_all_passport_data()
        max_count = min(count, len(all_passports))

        if max_count == 0:
            return []

        # Use secure random sampling
        indices = []
        for _ in range(max_count):
            idx = secrets.randbelow(len(all_passports))
            if idx not in indices:
                indices.append(idx)

        return [all_passports[i] for i in indices]


# Singleton instance for easy access
test_data_loader = TestDataLoader()
