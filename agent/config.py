"""Runtime configuration loaded from config.yml with environment overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import yaml
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yml"


@dataclass(frozen=True)
class RuntimeConfig:
    mcp_host: str
    mcp_port: int
    network_max_hosts: int
    network_max_ports: int
    network_max_concurrent: int
    network_timeout_seconds: int


def _section(config: dict, name: str) -> dict:
    value = config.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"Configuration section '{name}' must be a mapping.")
    return value


def _integer_setting(
    section: dict,
    setting: str,
    environment: Mapping[str, str],
    environment_name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw_value = environment.get(environment_name, section.get(setting, default))
    if isinstance(raw_value, bool) or not isinstance(raw_value, (int, str)):
        raise ValueError(f"{environment_name} must be an integer.")
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{environment_name} must be an integer.") from exc
    if value < minimum or value > maximum:
        raise ValueError(
            f"{environment_name} must be between {minimum} and {maximum}."
        )
    return value


def load_runtime_config(
    config_path: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> RuntimeConfig:
    """Load YAML defaults, then apply shell and .env environment overrides."""
    if environment is None:
        load_dotenv(PROJECT_ROOT / ".env")
        environment = os.environ

    path = config_path or DEFAULT_CONFIG_PATH
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {path}.") from exc

    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise ValueError(f"Configuration root in {path} must be a mapping.")

    mcp = _section(loaded, "mcp")
    network = _section(loaded, "network")
    host = environment.get("MCP_HOST", mcp.get("host", "127.0.0.1"))
    if not isinstance(host, str) or not host.strip():
        raise ValueError("MCP_HOST must be a non-empty hostname or IP address.")

    return RuntimeConfig(
        mcp_host=host.strip(),
        mcp_port=_integer_setting(
            mcp, "port", environment, "MCP_PORT", 8000, 1, 65535
        ),
        network_max_hosts=_integer_setting(
            network, "max_hosts", environment, "NETWORK_MAX_HOSTS", 256, 1, 256
        ),
        network_max_ports=_integer_setting(
            network, "max_ports", environment, "NETWORK_MAX_PORTS", 64, 1, 64
        ),
        network_max_concurrent=_integer_setting(
            network,
            "max_concurrent",
            environment,
            "NETWORK_MAX_CONCURRENT",
            32,
            1,
            256,
        ),
        network_timeout_seconds=_integer_setting(
            network,
            "timeout_seconds",
            environment,
            "NETWORK_REQUEST_TIMEOUT_SECONDS",
            3,
            1,
            300,
        ),
    )
