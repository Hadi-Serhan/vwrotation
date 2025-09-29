"""Core password rotation scheduler logic."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Iterable, List, Optional, Sequence

# NEW: for digest mode + dedupe
import os
import json
import hashlib
import pathlib

from .client import VaultwardenClient, CipherSelection
from .config import RotationPolicy


def _parse_timestamp(raw: Optional[str]) -> Optional[datetime]:
    if not raw:
        return None
    value = raw.strip()
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        pass
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


@dataclass(frozen=True)
class VaultItem:
    """Metadata the scheduler cares about for a Vaultwarden cipher."""

    id: str
    name: str
    user_id: Optional[str]
    collection_ids: Sequence[str]
    revision_date: datetime
    last_rotated_at: Optional[datetime]

    @property
    def effective_rotation_source(self) -> datetime:
        return self.last_rotated_at or self.revision_date

    @classmethod
    def from_api(cls, payload: Dict[str, object]) -> "VaultItem":
        cipher_id = str(payload.get("id"))
        name = str(payload.get("name") or payload.get("organizationId") or "Unnamed entry")
        user_id = payload.get("userId")
        revision = _parse_timestamp(str(payload.get("revisionDate", ""))) or datetime.now(timezone.utc)
        last_rotated = _parse_timestamp(str(payload.get("passwordRotation")))
        if not last_rotated:
            # Support proposed field name for new feature as shorthand.
            last_rotated = _parse_timestamp(str(payload.get("lastPasswordRotation")))
        collection_ids: Sequence[str] = []
        if isinstance(payload.get("collectionIds"), (list, tuple)):
            collection_ids = [str(cid) for cid in payload["collectionIds"]]
        elif payload.get("collectionId"):
            collection_ids = [str(payload.get("collectionId"))]
        return cls(
            id=cipher_id,
            name=name,
            user_id=str(user_id) if user_id else None,
            collection_ids=collection_ids,
            revision_date=revision,
            last_rotated_at=last_rotated,
        )


@dataclass(frozen=True)
class RotationCandidate:
    """Represents an item that is due (or nearly due) for rotation."""

    item: VaultItem
    due_at: datetime

    @property
    def overdue_delta(self) -> timedelta:
        now = datetime.now(timezone.utc)
        return now - self.due_at


class PasswordRotationScheduler:
    """Evaluates Vaultwarden data and sends rotation notifications."""

    def __init__(
        self,
        client: VaultwardenClient,
        policy: RotationPolicy,
        notifier,
        now_factory: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        user_email_resolver: Optional[Callable[[VaultItem], Optional[str]]] = None,
    ) -> None:
        self._client = client
        self._policy = policy
        self._notifier = notifier
        self._now_factory = now_factory
        self._user_email_resolver = user_email_resolver or self._resolve_email_via_client

    def run_once(self, send_notifications: bool = True) -> List[RotationCandidate]:
        ciphers = self._client.list_ciphers()
        selection = CipherSelection(ciphers)
        if self._policy.target_collections:
            selection = selection.filter_collections(self._policy.target_collections)
        if self._policy.target_users:
            selection = selection.filter_users(self._policy.target_users)

        items = [VaultItem.from_api(payload) for payload in selection.items]
        candidates = self._select_due_items(items)
        if send_notifications and candidates:
            self._dispatch_notifications(candidates)
        return candidates

    # ---- helpers ----------------------------------------------------------------
    def _select_due_items(self, items: Iterable[VaultItem]) -> List[RotationCandidate]:
        now = self._now_factory()
        due_items: List[RotationCandidate] = []
        frequency = self._policy.frequency_delta()
        grace = self._policy.grace_delta()
        reminder_threshold = frequency - grace

        for item in items:
            reference = item.effective_rotation_source
            due_at = reference + frequency
            # Send reminders when within reminder window or overdue
            if now >= reference + reminder_threshold:
                due_items.append(RotationCandidate(item=item, due_at=due_at))
        return due_items

    def _dispatch_notifications(self, candidates: Sequence[RotationCandidate]) -> None:
        if not candidates:
            return

        # SNS-only friendly: default to a single digest message per run.
        if os.getenv("ROTATION_SNS_DIGEST", "1").lower() in {"1", "true", "yes", "on"}:
            if not self._digest_has_changed(candidates):
                # No change since last run; avoid duplicate emails
                return
            policy_summary = self.build_policy_summary()
            self._notifier.send_rotation_notice("all", list(candidates), policy_summary)
            return

        # Fallback: per-recipient grouping (useful if later routing via Lambda/SES)
        grouped: Dict[str, List[RotationCandidate]] = {}
        for candidate in candidates:
            email = self._user_email_resolver(candidate.item)
            if not email:
                continue
            grouped.setdefault(email, []).append(candidate)

        if not grouped:
            return

        policy_summary = self.build_policy_summary()
        for recipient, items in grouped.items():
            self._notifier.send_rotation_notice(recipient, items, policy_summary)

    def _digest_has_changed(self, candidates: Sequence[RotationCandidate]) -> bool:
        """Persist a content hash so repeated runs with identical due sets don’t resend."""
        state_file = os.getenv("ROTATION_STATE_FILE", ".rotation_state.json")
        payload = [{"id": c.item.id, "due": c.due_at.isoformat()} for c in candidates]
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
        path = pathlib.Path(state_file)
        prev = None
        if path.exists():
            try:
                prev = json.loads(path.read_text()).get("last_hash")
            except Exception:
                prev = None
        if digest == prev:
            return False
        try:
            path.write_text(json.dumps({"last_hash": digest}))
        except Exception:
            # Best-effort only; don't crash if state file isn't writable
            pass
        return True

    def _resolve_email_via_client(self, item: VaultItem) -> Optional[str]:
        return self._client.resolve_user_email(item.user_id)

    def build_policy_summary(self) -> str:
        parts = [f"frequency {self._policy.frequency_days}d"]
        if self._policy.grace_period_days:
            parts.append(f"grace {self._policy.grace_period_days}d")
        if self._policy.target_collections:
            parts.append(f"collections {len(self._policy.target_collections)}")
        if self._policy.target_users:
            parts.append(f"users {len(self._policy.target_users)}")
        return ", ".join(parts)
