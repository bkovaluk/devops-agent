"""Environment-driven settings for the DevOps agent Lambda."""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Annotated, Any, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

Environment = Literal["dev", "qa", "staging", "prod"]

_ACCOUNT_ID = re.compile(r"^\d{12}$")


class Settings(BaseSettings):
    """Lambda configuration read from environment variables."""

    model_config = SettingsConfigDict(env_prefix="", protected_namespaces=())

    environment: Environment = "dev"
    findings_table: str
    # Critical and high findings go to this SNS topic when enabled; findings are always stored.
    slack_enabled: bool = False
    slack_topic_arn: str | None = Field(
        default=None, pattern=r"^arn:aws[a-z-]*:sns:[a-z0-9-]+:\d{12}:[A-Za-z0-9_-]{1,256}$"
    )
    slack_channel: str = ""
    model_id: str = "us.anthropic.claude-opus-5-5"
    fallback_model_id: str = "us.anthropic.claude-opus-5"
    max_steps: int = Field(default=14, ge=1)
    # A report_finding call alone runs past 2,048 tokens; a cut-off call loses its last fields.
    max_tokens: int = Field(default=8192, ge=256)
    # Bedrock cache checkpoints on the tools, the system prompt and the conversation.
    prompt_caching: bool = True
    # Cost-weighted tokens (agent.weighted_tokens) one investigation may spend before its
    # final step.
    run_token_budget: int = Field(default=250_000, ge=1)
    aws_region: str = "us-east-1"
    log_level: str = "INFO"
    # Writes snap#<finding_id> (the job, context bundle and tool calls) for eval replay.
    capture_snapshots: bool = True
    # Name or ARN of the SSM parameter holding this deployment's catalog document; unset
    # runs on the catalog bundled with the package.
    catalog_parameter: str | None = None
    # The Datadog tools are offered, and triage verifies Datadog signals, only when both
    # keys are set. The app key should belong to a read-only service account.
    dd_api_key: SecretStr | None = None
    datadog_app_key: SecretStr | None = None
    datadog_site: str = Field(
        default="datadoghq.com",
        pattern=r"^(?:[a-z0-9]+\.)?(?:datadoghq\.com|datadoghq\.eu|ddog-gov\.com)$",
    )
    # The GitHub tools are offered only when all three App credentials and GH_ORG are set.
    # The App reads GH_ORG only.
    gh_app_id: str | None = Field(default=None, pattern=r"^\d{0,20}$")
    gh_app_installation_id: str | None = Field(default=None, pattern=r"^\d{0,20}$")
    gh_app_private_key: SecretStr | None = None
    gh_org: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")

    # Operator-provided text about this deployment (naming conventions, where code and
    # infrastructure live), appended to the system prompt when set.
    prompt_notes: str = ""

    # Many accounts: the read-only role every member account lends the agent. Unset, the
    # agent reads only the account it runs in.
    member_role_name: str | None = Field(default=None, pattern=r"^[\w+=,.@-]{1,64}$")
    member_external_id: str | None = Field(
        default=None, min_length=2, max_length=1224, pattern=r"^[\w+=,.@:/-]+$"
    )
    # When set, signals from any other account are refused.
    allowed_account_ids: Annotated[frozenset[str], NoDecode] = frozenset()
    # The Datadog monitor tag whose value names the AWS account a monitor watches.
    datadog_account_tag: str = Field(default="aws_account", pattern=r"^[a-z][a-z0-9_.-]{0,99}$")

    @field_validator("allowed_account_ids", mode="before")
    @classmethod
    def _account_list(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = [part.strip() for part in value.split(",") if part.strip()]
        if isinstance(value, list | tuple | set | frozenset):
            invalid = [item for item in value if not _ACCOUNT_ID.match(str(item))]
            if invalid:
                raise ValueError(f"not 12-digit account ids: {', '.join(map(str, invalid))}")
            return frozenset(str(item) for item in value)
        return value

    @model_validator(mode="after")
    def _topic_set_when_enabled(self) -> Settings:
        if self.slack_enabled and not self.slack_topic_arn:
            raise ValueError("slack_topic_arn is required when slack_enabled is true")
        return self

    @property
    def multi_account(self) -> bool:
        """True when member accounts lend a role: budgets and metrics then count per account."""
        return bool(self.member_role_name)


class TriageSettings(Settings):
    """Settings for the triage Lambda, which alone emits work and spends the budgets."""

    work_queue_url: str
    # Budget-deferred alarms go back here, delayed, while they stay in the same episode.
    alarms_queue_url: str
    max_deferred_retries: int = Field(default=8, ge=0)
    storm_threshold: int = Field(default=5, ge=2)
    hourly_budget: int = Field(default=10, ge=0)
    daily_budget: int = Field(default=50, ge=0)
    # Cost-weighted tokens all investigations may spend in a (UTC) day.
    daily_token_budget: int = Field(default=3_000_000, ge=0)
    alarm_cooldown_minutes: int = Field(default=120, ge=0)
    resource_cooldown_minutes: int = Field(default=60, ge=0)
    # Priority 1 jobs past the hourly budget, at most this many a (UTC) day.
    p1_daily_overflow: int = Field(default=10, ge=0)
    # The last share of the hourly budget that priority 3 and 4 jobs may not use.
    reserve_fraction: float = Field(default=0.3, ge=0, le=1)
    # Jobs about a Datadog signal, at most this many of the hourly budget.
    datadog_hourly_share: int = Field(default=6, ge=0)
    # Signals per 5-minute bucket above which two buckets in a row are a storm.
    storm_rate: int = Field(default=30, ge=1)
    # With member accounts, the jobs one account may use of the hourly and daily budgets.
    account_hourly_budget: int = Field(default=5, ge=0)
    account_daily_budget: int = Field(default=25, ge=0)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


@lru_cache(maxsize=1)
def get_triage_settings() -> TriageSettings:
    return TriageSettings()  # type: ignore[call-arg]
