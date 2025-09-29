"""Notification helpers for the password rotation scheduler."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timezone
from typing import List, Optional, Sequence, TYPE_CHECKING
import os
import time

from .config import NotificationConfig

if TYPE_CHECKING:  # pragma: no cover
    from .scheduler import RotationCandidate


@dataclass(frozen=True)
class NotificationResult:
    """Represents a successfully queued email notification."""
    recipient: str
    message_id: str


class AWSSNSNotifier:
    """Wrapper around AWS SNS for distributing rotation reminders."""

    def __init__(self, config: NotificationConfig, sns_client: Optional[object] = None) -> None:
        self._config = config
        if sns_client is not None:
            self._sns = sns_client
            self._client_error_cls = Exception  # fallback
        else:
            try:
                import boto3
                from botocore.exceptions import ClientError
                self._client_error_cls = ClientError
            except ImportError as exc:  # pragma: no cover - import failure path
                raise RuntimeError("boto3 is required for AWS SNS notifications") from exc

            session_kwargs = {"region_name": config.region}
            if config.access_key and config.secret_key:
                session_kwargs.update(
                    aws_access_key_id=config.access_key,
                    aws_secret_access_key=config.secret_key,
                )
            endpoint_url = os.getenv("AWS_ENDPOINT_URL")  # e.g. http://localhost:4566 for LocalStack
            if endpoint_url:
                self._sns = boto3.client("sns", endpoint_url=endpoint_url, **session_kwargs)
            else:
                self._sns = boto3.client("sns", **session_kwargs)

    def send_rotation_notice(
        self,
        recipient: str,
        items: Sequence["RotationCandidate"],
        policy_summary: str,
    ) -> NotificationResult:
        """Publish a rotation reminder message to the configured SNS topic."""

        subject_prefix = (self._config.subject_prefix or "Vaultwarden").encode("ascii", "ignore").decode("ascii")
        subject = f"{subject_prefix} password rotation reminder"[:100]  # SNS Subject must be ASCII, <= 100 chars
        body_text = self._build_plaintext_body(recipient, items, policy_summary)

        message_attributes = {
            "recipient": {"DataType": "String", "StringValue": recipient}
        }

        # Simple retry/backoff for throttling & transient errors
        last_exc: Optional[Exception] = None
        for attempt in range(5):
            try:
                response = self._sns.publish(
                    TopicArn=self._config.topic_arn,
                    Subject=subject,
                    Message=body_text,
                    MessageAttributes=message_attributes,
                )
                message_id = response.get("MessageId", "")
                return NotificationResult(recipient=recipient, message_id=message_id)
            except self._client_error_cls as e:  # type: ignore
                # On throttling / 5xx, backoff; otherwise re-raise
                code = getattr(e, "response", {}).get("Error", {}).get("Code")
                if code in {"Throttling", "InternalError", "ServiceUnavailable"} and attempt < 4:
                    time.sleep(2 ** attempt)  # 1,2,4,8 seconds
                    last_exc = e
                    continue
                raise
            except Exception as e:
                if attempt < 4:
                    time.sleep(2 ** attempt)
                    last_exc = e
                    continue
                raise
        # If we somehow exit the loop without returning/raising earlier
        if last_exc:
            raise last_exc
        return NotificationResult(recipient=recipient, message_id="")

    # ---------- Email body helpers ----------

    def _build_plaintext_body(
        self,
        recipient: str,
        items: Sequence["RotationCandidate"],
        policy_summary: str,
    ) -> str:
        max_lines = int(os.getenv("ROTATION_SNS_MAX_LINES", "100"))
        base_url = os.getenv("VAULTWARDEN_URL", "").strip()

        lines: List[str] = [
            "Hello,",
            "",
            "The following Vaultwarden entries are due for password rotation:",
            "",
        ]

        for i, candidate in enumerate(items):
            if i >= max_lines:
                lines.append(f"... and {len(items) - max_lines} more")
                break

            due_utc = candidate.due_at.astimezone(timezone.utc)
            due_str = due_utc.strftime("%Y-%m-%d %H:%M UTC")

            label = self._label_for(candidate)
            full_id = candidate.item.id or "unknown-id"

            lines.append(f"- {label} (due {due_str})")
            lines.append(f"  ID: {full_id}")

            if base_url and full_id != "unknown-id":
                lines.append(f"  Link: {self._item_link(base_url, full_id)}")

        lines.extend(
            [
                "",
                f"Policy: {policy_summary}",
                "",
                "Please rotate these passwords at your earliest convenience.",
                "If you have already updated them, you can ignore this reminder.",
                "",
                "— Vaultwarden",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _item_link(base_url: str, item_id: str) -> str:
        # base_url like "http://localhost:3000" -> "http://localhost:3000/#/vault?itemId=<id>"
        base = base_url.rstrip("/")
        return f"{base}/#/vault?itemId={item_id}"

    @staticmethod
    def _looks_encrypted(s: Optional[str]) -> bool:
        # Typical encrypted shape: "<encType>.<b64>|<b64>|<b64>" and quite long
        if not s:
            return False
        return ("|" in s and "." in s) or len(s) > 60

    @staticmethod
    def _type_label(candidate: "RotationCandidate") -> str:
        # If you added cipher_type to VaultItem, show a type; otherwise generic "Item"
        TYPE_LABEL = {1: "Login", 2: "SecureNote", 3: "Card", 4: "Identity"}
        t = getattr(candidate.item, "cipher_type", None)
        return TYPE_LABEL.get(t, "Item")

    def _label_for(self, candidate: "RotationCandidate") -> str:
        name = getattr(candidate.item, "name", "") or "(Unnamed)"
        if self._looks_encrypted(name):
            short_id = (candidate.item.id or "")[:8] or "unknown"
            return f"({self._type_label(candidate)}) ID:{short_id}"
        return name
