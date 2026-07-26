"""Configuration loading and validation."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
ResponseMode = Literal["audit", "active"]


def default_rules_path() -> str:
    """Return the built-in rule file installed with the Python package."""

    return str(Path(__file__).with_name("rules") / "builtin.yml")


class AgentConfig(BaseModel):
    id: str = "bait-local-agent"
    interval_seconds: int = Field(default=10, ge=1, le=3600)
    database_path: str = "./data/bait.db"
    rules_path: str = Field(default_factory=default_rules_path)
    log_level: LogLevel = "INFO"


class ApiConfig(BaseModel):
    bind_host: str = "127.0.0.1"
    bind_port: int = Field(default=8765, ge=1, le=65535)
    token_env: str = "BAIT_API_TOKEN"


class ResponseConfig(BaseModel):
    mode: ResponseMode = "audit"
    quarantine_directory: str = "./data/quarantine"
    allow_process_termination: bool = False
    allow_file_quarantine: bool = False
    protected_process_names: list[str] = Field(default_factory=list)
    allowed_quarantine_roots: list[str] = Field(default_factory=list)


class PrivacyConfig(BaseModel):
    capture_command_line: bool = True
    capture_username: bool = True
    redact_environment_variables: bool = True
    event_retention_days: int = Field(default=30, ge=1, le=3650)


class Settings(BaseModel):
    agent: AgentConfig = Field(default_factory=AgentConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)

    @property
    def api_token(self) -> str | None:
        token = os.getenv(self.api.token_env)
        return token if token else None


def load_settings(path: str | Path | None = None) -> Settings:
    """Load settings from YAML, or return secure defaults when the file is absent."""

    if path is None:
        path = os.getenv("BAIT_CONFIG", "config.yml")
    config_path = Path(path)
    if not config_path.exists():
        return Settings()
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            payload: dict[str, Any] = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in configuration file {config_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Configuration file {config_path} must contain a YAML mapping")
    return Settings.model_validate(payload)
