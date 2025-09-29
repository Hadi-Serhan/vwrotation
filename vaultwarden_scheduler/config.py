"""Configuration dataclasses for the Vaultwarden password rotation scheduler."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional, Sequence


@dataclass(frozen=True)
class VaultwardenConfig:
    """Connection details for talking to Vaultwarden's HTTP API."""

    base_url: str
    client_id: str
    client_secret: str
    timeout_seconds: int = 10
    audience: Optional[str] = None


@dataclass(frozen=True)
class RotationPolicy:
    """Defines when an item becomes due for password rotation."""

    frequency_days: int
    grace_period_days: int = 0
    target_collections: Optional[Sequence[str]] = None
    target_users: Optional[Sequence[str]] = None
    send_digest: bool = True

    def frequency_delta(self) -> timedelta:
        return timedelta(days=self.frequency_days)

    def grace_delta(self) -> timedelta:
        return timedelta(days=self.grace_period_days)


@dataclass(frozen=True)
class NotificationConfig:
    """Configuration for outbound SNS notifications."""

    region: str
    topic_arn: str
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    subject_prefix: Optional[str] = None
