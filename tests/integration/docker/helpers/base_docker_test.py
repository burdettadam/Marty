"""Legacy BaseDockerIntegrationTest stub (deprecated).

All tests now use OrchestratedIntegrationTest. This file remains only to
avoid import errors for any external tooling and contains no functionality.
It can be safely deleted once confirmed unused externally.
"""


class BaseDockerIntegrationTest:  # pragma: no cover
    """Deprecated test base class - use OrchestratedIntegrationTest instead."""

    @classmethod
    def shutdown_docker_services(cls):
        """No-op legacy hook."""
        return
