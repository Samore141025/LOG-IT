from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml
from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    url: str = Field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg2://postgres:postgres@localhost:5432/shugo_cyber"
        )
    )
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 1800


class GeminiConfig(BaseModel):
    api_key: Optional[str] = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY"))
    model: str = Field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))
    temperature: float = 0.1
    timeout_seconds: float = 60.0
    max_retries: int = 3
    rate_limit_rpm: int = 15
    rate_limit_rpd: int = 1500


class RedactionConfig(BaseModel):
    mask_passwords: bool = True
    mask_tokens: bool = True
    mask_cookies: bool = True
    hash_internal_ips: bool = False
    internal_ip_prefixes: list[str] = Field(default_factory=lambda: ["10.", "172.16.", "192.168."])


class AgentRuntimeConfig(BaseModel):
    agent_name: str = "log_analysis"
    batch_size: int = 500
    poll_interval_idle_seconds: float = 5.0
    poll_interval_busy_seconds: float = 0.5
    heartbeat_interval_seconds: float = 15.0
    max_memory_window_minutes: int = 120


class Config(BaseModel):
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    gemini: GeminiConfig = Field(default_factory=GeminiConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    runtime: AgentRuntimeConfig = Field(default_factory=AgentRuntimeConfig)
    raw_yaml: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def load(cls, yaml_path: Optional[str | Path] = None) -> Config:
        data: Dict[str, Any] = {}
        if yaml_path:
            p = Path(yaml_path)
            if p.is_file():
                with open(p, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if isinstance(loaded, dict):
                        data = loaded

        db_data = data.get("database", {})
        gemini_data = data.get("gemini", {})
        redaction_data = data.get("redaction", {})
        runtime_data = data.get("runtime", {})

        return cls(
            database=DatabaseConfig(**db_data),
            gemini=GeminiConfig(**gemini_data),
            redaction=RedactionConfig(**redaction_data),
            runtime=AgentRuntimeConfig(**runtime_data),
            raw_yaml=data
        )
