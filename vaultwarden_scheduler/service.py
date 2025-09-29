"""CLI entry point for running the Vaultwarden password rotation scheduler."""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Optional, Sequence

from dotenv import find_dotenv, load_dotenv

from .client import VaultwardenClient
from .config import NotificationConfig, RotationPolicy, VaultwardenConfig
from .notification import AWSSNSNotifier
from .scheduler import PasswordRotationScheduler

LOGGER = logging.getLogger("vaultwarden_scheduler.service")


def _split_env(name: str) -> Optional[Sequence[str]]:
    raw = os.getenv(name, "")
    parts = [value.strip() for value in raw.split(",") if value.strip()]
    return parts if parts else None


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


def build_scheduler_from_env() -> PasswordRotationScheduler:
    load_dotenv(find_dotenv(), override=False)

    for required in ("VAULTWARDEN_URL", "CLIENT_ID", "CLIENT_SECRET", "ROTATION_SNS_TOPIC_ARN", "AWS_SNS_REGION"):
        if not os.getenv(required):
            LOGGER.error("Environment variable %s is required", required)
            raise SystemExit(1)

    vault_config = VaultwardenConfig(
        base_url=os.environ["VAULTWARDEN_URL"],
        client_id=os.environ["CLIENT_ID"],
        client_secret=os.environ["CLIENT_SECRET"],
    )

    policy = RotationPolicy(
        frequency_days=int(os.getenv("ROTATION_FREQUENCY_DAYS", "90")),
        grace_period_days=int(os.getenv("ROTATION_GRACE_PERIOD_DAYS", "5")),
        target_collections=_split_env("ROTATION_COLLECTION_IDS"),
        target_users=_split_env("ROTATION_USER_IDS"),
    )

    notification_config = NotificationConfig(
        region=os.environ["AWS_SNS_REGION"],
        topic_arn=os.environ["ROTATION_SNS_TOPIC_ARN"],
        access_key=os.getenv("AWS_SNS_ACCESS_KEY_ID"),
        secret_key=os.getenv("AWS_SNS_SECRET_ACCESS_KEY"),
        subject_prefix=os.getenv("ROTATION_SUBJECT_PREFIX"),
    )

    client = VaultwardenClient(vault_config)
    notifier = AWSSNSNotifier(notification_config)
    return PasswordRotationScheduler(client=client, policy=policy, notifier=notifier)


def run_scheduler_loop() -> None:
    scheduler = build_scheduler_from_env()
    poll_seconds = int(os.getenv("ROTATION_POLL_SECONDS", "3600"))
    dry_run = _bool_env("ROTATION_DRY_RUN", default=False)
    run_once = _bool_env("ROTATION_RUN_ONCE", default=False)

    LOGGER.info(
        "Starting rotation scheduler (poll every %ss, dry_run=%s, once=%s)",
        poll_seconds,
        dry_run,
        run_once,
    )

    def execute_once() -> None:
        start = time.monotonic()
        try:
            candidates = scheduler.run_once(send_notifications=not dry_run)
            LOGGER.info("Scheduler run complete. Candidates=%s", len(candidates))
        except Exception:  # pragma: no cover - defensive logging path
            LOGGER.exception("Rotation scheduler run failed")
        finally:
            elapsed = time.monotonic() - start
            LOGGER.debug("Run duration %.2fs", elapsed)

    execute_once()
    if run_once:
        return

    while True:
        time.sleep(poll_seconds)
        execute_once()


def main(argv: Optional[Sequence[str]] = None) -> int:  # noqa: D401
    """Entry point when executing the module with `python -m`."""

    logging.basicConfig(level=os.getenv("ROTATION_LOG_LEVEL", "INFO"))
    try:
        run_scheduler_loop()
    except KeyboardInterrupt:
        LOGGER.info("Scheduler stopped via KeyboardInterrupt")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
