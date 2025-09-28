"""Backward-compatible shim for running Marty microservices.

The historic entrypoint used the SERVICE_NAME environment variable to decide
which service to boot. Deployment is now split so each microservice exposes its
own module under ``src.apps``. This shim accepts an explicit service name to ease
transition and guides callers towards the dedicated entrypoints.
"""

from __future__ import annotations

import sys
from typing import Sequence

from apps.runtime import SERVICE_DEFINITIONS, ServiceDefinition, serve_service


def available_services() -> list[str]:
    """Return the sorted list of known service names."""
    return sorted(SERVICE_DEFINITIONS)


def resolve_service(name: str) -> ServiceDefinition:
    try:
        return SERVICE_DEFINITIONS[name]
    except KeyError as exc:  # pragma: no cover - defensive guard
        valid = ", ".join(available_services())
        raise ValueError(f"Unknown service '{name}'. Valid options: {valid}") from exc


def serve(service_name: str) -> None:
    """Start a specific microservice by name."""
    definition = resolve_service(service_name)
    serve_service(definition)


def main(argv: Sequence[str] | None = None) -> None:
    args = list(argv or sys.argv[1:])
    if not args:
        valid = ", ".join(available_services())
        raise SystemExit(
            "src/main.py is deprecated. Choose an explicit service entrypoint, e.g. "
            "'python -m src.apps.csca_service'.\n"
            f"Known services: {valid}"
        )

    serve(args[0])


if __name__ == "__main__":
    main()
