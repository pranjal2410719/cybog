"""
cybog/config/models.py — Pydantic models for config.yaml.
"""
from __future__ import annotations
import os
from pydantic import BaseModel, Field, model_validator


class ToolConfig(BaseModel):
    enabled: bool = True
    binary: str
    timeout: int = 300
    extra_args: list[str] = Field(default_factory=list)


class FfufToolConfig(ToolConfig):
    wordlist: str = "./config/wordlists/common.txt"


class NucleiToolConfig(ToolConfig):
    severity: str = "low,medium,high,critical"
    templates: str = ""


class AuthToolConfig(ToolConfig):
    credentials: str = ""
    auth_method: str = "basic"  # basic | digest | bearer | custom
    auth_url: str = ""
    extra_args: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _load_credentials_from_env(self) -> "AuthToolConfig":
        """
        Credentials default to empty and are read from CYBOG_AUTH_CREDENTIALS.

        This keeps secrets out of config.yaml and out of version control. When
        unset the field stays empty, which makes auth validation report itself
        as not-applicable rather than failing an unrelated scan.
        """
        if not self.credentials:
            env_value = os.environ.get("CYBOG_AUTH_CREDENTIALS", "")
            if env_value:
                object.__setattr__(self, "credentials", env_value)
        return self

    def is_configured(self) -> bool:
        return bool(self.credentials)


class ToolsConfig(BaseModel):
    subfinder: ToolConfig = Field(default_factory=lambda: ToolConfig(binary="subfinder"))
    dnsx: ToolConfig = Field(default_factory=lambda: ToolConfig(binary="dnsx"))
    httpx: ToolConfig = Field(default_factory=lambda: ToolConfig(binary="httpx"))
    naabu: ToolConfig = Field(default_factory=lambda: ToolConfig(binary="naabu", timeout=600))
    katana: ToolConfig = Field(default_factory=lambda: ToolConfig(binary="katana", timeout=600))
    ffuf: FfufToolConfig = Field(default_factory=lambda: FfufToolConfig(binary="ffuf", timeout=600))
    nuclei: NucleiToolConfig = Field(default_factory=lambda: NucleiToolConfig(binary="nuclei", timeout=900))
    auth: AuthToolConfig = Field(
        default_factory=lambda: AuthToolConfig(binary="httpx", enabled=False)
    )


class WorkersConfig(BaseModel):
    subfinder: int = 4
    dnsx: int = 8
    httpx: int = 8
    naabu: int = 4
    katana: int = 4
    ffuf: int = 2
    nuclei: int = 4


class QueuesConfig(BaseModel):
    max_size: int = 100


class PipelineConfig(BaseModel):
    profile: str = "standard"


class TargetsConfig(BaseModel):
    input: str = "./targets.txt"
    batch_size: int = 100


class AuthorizationConfig(BaseModel):
    required: bool = True
    scope_file: str = "./authorized_scope.txt"


class ExecutionConfig(BaseModel):
    continue_on_error: bool = True
    retry_failed: int = 2
    resume: bool = True


class OutputConfig(BaseModel):
    root: str = "./reports"


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "json"


class CybogConfig(BaseModel):
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    targets: TargetsConfig = Field(default_factory=TargetsConfig)
    authorization: AuthorizationConfig = Field(default_factory=AuthorizationConfig)
    workers: WorkersConfig = Field(default_factory=WorkersConfig)
    queues: QueuesConfig = Field(default_factory=QueuesConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
