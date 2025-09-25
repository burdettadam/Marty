"""
Configuration loading utilities for Marty services.

This module provides functionality to load and parse configuration files
based on environment (development, testing, production).
"""

import os
from pathlib import Path
from typing import Any, Optional

import yaml


class ConfigurationError(Exception):
    """Raised when there's an error loading configuration."""


class Config:
    """Minimal configuration object used by several services and tests.

    This wrapper provides attribute-style access to service configuration
    sections from the loaded YAML. Only the behavior that tests rely on is
    implemented; new fields can be added as needed.
    """

    def __init__(self, environment: Optional[str] = None) -> None:
        self._environment = (environment or get_environment()).lower()
        self._config = load_config(self._environment)

    @property
    def environment(self) -> str:
        """Get the current environment name (development, testing, production)."""
        return self._environment

    def get_service(self, service_name: str) -> dict[str, Any]:
        """Get configuration for a specific service by name."""
        return get_service_config(service_name, self._environment)

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key with optional default."""
        return self._config.get(key, default)

    def __getitem__(self, item: str) -> Any:
        return self._config[item]


def get_environment() -> str:
    """
    Get the current environment from MARTY_ENV environment variable.
    Defaults to 'development' if not set.
    """
    return os.environ.get("MARTY_ENV", "development").lower()


def get_config_path(environment: Optional[str] = None) -> Path:
    """
    Get the path to the configuration file for the specified environment.

    Args:
        environment: The environment to use. If None, uses the value from get_environment()

    Returns:
        Path to the configuration file
    """
    if environment is None:
        environment = get_environment()

    # Project root directory is two levels up from this file
    project_root = Path(__file__).parent.parent.parent
    config_path = project_root / "config" / f"{environment}.yaml"

    if not config_path.exists():
        msg = f"Configuration file not found: {config_path}"
        raise ConfigurationError(msg)

    return config_path


def load_config(environment: Optional[str] = None) -> dict[str, Any]:
    """
    Load configuration from the appropriate YAML file based on environment.

    Args:
        environment: The environment to use. If None, uses the value from get_environment()

    Returns:
        Dictionary containing the configuration
    """
    config_path = get_config_path(environment)

    try:
        with open(config_path) as f:
            config = yaml.safe_load(f)

        # Expand environment variables in strings
        return _expand_env_vars(config)

    except Exception as e:
        msg = f"Error loading configuration: {e!s}"
        raise ConfigurationError(msg)


def _expand_env_vars(config: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively expand environment variables in configuration strings.

    Args:
        config: Configuration dictionary

    Returns:
        Configuration with environment variables expanded
    """
    result = {}

    for key, value in config.items():
        if isinstance(value, dict):
            result[key] = _expand_env_vars(value)
        elif isinstance(value, str) and "${" in value and "}" in value:
            # Extract environment variable name
            env_var = value.split("${")[1].split("}")[0]
            env_value = os.environ.get(env_var)

            if env_value is not None:
                result[key] = value.replace(f"${{{env_var}}}", env_value)
            else:
                # Keep the original if environment variable is not set
                result[key] = value
        else:
            result[key] = value

    return result


def get_service_config(service_name: str, environment: Optional[str] = None) -> dict[str, Any]:
    """
    Get configuration specific to a service.

    Args:
        service_name: The name of the service
        environment: The environment to use. If None, uses the value from get_environment()

    Returns:
        Service-specific configuration
    """
    config = load_config(environment)

    # Common configuration for all services
    result = {
        "environment": get_environment(),
        "logging": config.get("logging", {}),
    }

    # Add service-specific configuration if available
    if "services" in config and service_name in config["services"]:
        result.update(config["services"][service_name])

    # Add general configuration
    if "ports" in config and service_name in config["ports"]:
        result["port"] = config["ports"][service_name]

    if "hosts" in config and service_name in config["hosts"]:
        result["host"] = config["hosts"][service_name]

    return result
