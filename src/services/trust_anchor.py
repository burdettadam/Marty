import json
import logging
import os
from typing import Optional

# Import the generated gRPC modules
from src.proto import trust_anchor_pb2, trust_anchor_pb2_grpc


class TrustAnchor(trust_anchor_pb2_grpc.TrustAnchorServicer):
    """
    Implementation of the Trust Anchor service.

    This service is responsible for:
    - Maintaining trusted CSCA certificate lists
    - Synchronizing with ICAO PKD or private mirrors
    - Updates Certificate Revocation Lists (CRLs)
    """

    def __init__(self, channels=None) -> None:
        """
        Initialize the Trust Anchor service.

        Args:
            channels (dict): Dictionary of gRPC channels to other services
        """
        self.logger = logging.getLogger(__name__)
        self.channels = channels or {}
        self.data_dir = os.environ.get("DATA_DIR", "/app/data")
        self.logger.info("Trust Anchor service initialized")

        # Initialize trust store
        self.trust_store = self._load_trust_store()

    def _load_trust_store(self):
        """
        Load the trust store from disk or initialize a new one.

        Returns:
            dict: The trust store dictionary
        """
        trust_store_path = os.path.join(self.data_dir, "trust_store.json")

        if os.path.exists(trust_store_path):
            try:
                with open(trust_store_path) as f:
                    return json.load(f)
            except Exception as e:
                self.logger.exception(f"Error loading trust store: {e}")

        # Default trust store
        default_trust_store = {
            "trusted_entities": {
                "csca-service": True,
                "document-signer": True,
                "inspection-system": True,
                "passport-engine": True,
                "test-entity": True,
            },
            "revoked_entities": [],
        }

        # Save default trust store to disk
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            with open(trust_store_path, "w") as f:
                json.dump(default_trust_store, f, indent=2)
        except Exception as e:
            self.logger.exception(f"Error saving default trust store: {e}")

        return default_trust_store

    def VerifyTrust(self, request, context):
        """
        Verify if an entity is trusted.

        Args:
            request: The gRPC request containing the entity to verify
            context: The gRPC context

        Returns:
            TrustResponse: The gRPC response containing whether the entity is trusted
        """
        entity = request.entity
        self.logger.info(f"VerifyTrust called for entity: {entity}")

        # Check if the entity is in the trusted entities list
        is_trusted = self.trust_store.get("trusted_entities", {}).get(entity, False)

        # Check if the entity is in the revoked entities list
        if entity in self.trust_store.get("revoked_entities", []):
            is_trusted = False

        self.logger.info(f"Entity {entity} is trusted: {is_trusted}")

        # Return the response
        return trust_anchor_pb2.TrustResponse(is_trusted=is_trusted)

    def update_trust_store(self, entity, trusted=True) -> Optional[bool]:
        """
        Update the trust store with a new entity or update an existing one.

        Args:
            entity (str): The entity to update
            trusted (bool): Whether the entity is trusted

        Returns:
            bool: True if the update was successful, False otherwise
        """
        try:
            if trusted:
                # Add to trusted entities
                self.trust_store["trusted_entities"][entity] = True

                # Remove from revoked entities if present
                if entity in self.trust_store.get("revoked_entities", []):
                    self.trust_store["revoked_entities"].remove(entity)
            else:
                # Remove from trusted entities if present
                if entity in self.trust_store.get("trusted_entities", {}):
                    del self.trust_store["trusted_entities"][entity]

                # Add to revoked entities
                if entity not in self.trust_store.get("revoked_entities", []):
                    self.trust_store.setdefault("revoked_entities", []).append(entity)

            # Save updated trust store to disk
            trust_store_path = os.path.join(self.data_dir, "trust_store.json")
            with open(trust_store_path, "w") as f:
                json.dump(self.trust_store, f, indent=2)

            self.logger.info(f"Trust store updated for entity {entity}, trusted={trusted}")
            return True
        except Exception as e:
            self.logger.exception(f"Error updating trust store: {e}")
            return False
