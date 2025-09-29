"""Thin HTTP client around the Vaultwarden API used by the scheduler."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from collections.abc import Iterable as IterableABC
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

import requests

from .config import VaultwardenConfig


class VaultwardenClient:
    """Wrapper for Vaultwarden API endpoints needed by the scheduler."""

    def __init__(self, config: VaultwardenConfig, session: Optional[requests.Session] = None) -> None:
        self._config = config
        self._session = session or requests.Session()
        self._base_url = config.base_url.rstrip("/")
        self._token: Optional[str] = None
        self._token_expiry_epoch: float = 0.0
        self._profile_cache: Optional[Dict[str, Any]] = None
        self._user_email_cache: Dict[str, str] = {}

    # ---- authentication helpers -------------------------------------------------
    def _token_is_valid(self) -> bool:
        return bool(self._token) and time.time() < (self._token_expiry_epoch - 15)

    def _obtain_token(self) -> None:
        data = {
            "grant_type": "client_credentials",
            "scope": "api",
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
            "deviceIdentifier": str(uuid.uuid4()),
            "deviceType": "7",
            "deviceName": "rotation-scheduler",
        }
        if self._config.audience:
            data["audience"] = self._config.audience

        response = self._session.post(
            urljoin(self._base_url + "/", "identity/connect/token"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            timeout=self._config.timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        self._token = payload["access_token"]
        expires_in = int(payload.get("expires_in", 3600))
        self._token_expiry_epoch = time.time() + expires_in

    def _auth_headers(self) -> Dict[str, str]:
        if not self._token_is_valid():
            self._obtain_token()
        assert self._token  # for type-checkers
        return {"Authorization": f"Bearer {self._token}"}

    # ---- public API --------------------------------------------------------------
    def list_ciphers(self) -> List[Dict[str, Any]]:
        response = self._session.get(
            urljoin(self._base_url + "/", "api/ciphers"),
            headers=self._auth_headers(),
            timeout=self._config.timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict) and "data" in payload:
            return list(payload["data"])
        if isinstance(payload, list):
            return payload
        raise ValueError("Unexpected response from /api/ciphers")

    def get_profile(self) -> Dict[str, Any]:
        if self._profile_cache is None:
            response = self._session.get(
                urljoin(self._base_url + "/", "api/accounts/profile"),
                headers=self._auth_headers(),
                timeout=self._config.timeout_seconds,
            )
            response.raise_for_status()
            self._profile_cache = response.json()
        return self._profile_cache

    def resolve_user_email(self, user_id: Optional[str]) -> Optional[str]:
        """Resolve a Vaultwarden user id to an email address."""

        if not user_id:
            profile = self.get_profile()
            return profile.get("email")

        if user_id in self._user_email_cache:
            return self._user_email_cache[user_id]

        # Fallback strategy: try organization members endpoint if org context present
        # This keeps the client usable without needing every upstream change immediately.
        profile = self.get_profile()
        org_id = profile.get("organizationId")
        if org_id:
            response = self._session.get(
                urljoin(self._base_url + "/", f"api/organizations/{org_id}/users"),
                headers=self._auth_headers(),
                timeout=self._config.timeout_seconds,
            )
            if response.status_code == 200:
                for entry in response.json().get("data", []):
                    if entry.get("id") == user_id:
                        email = entry.get("email")
                        if email:
                            self._user_email_cache[user_id] = email
                            return email

        # As a final fallback return profile email to avoid dropping notifications entirely.
        return profile.get("email")

    def update_cipher_password(self, cipher_id: str, new_password: str) -> Dict[str, Any]:
        payload = {"password": new_password}
        response = self._session.put(
            urljoin(self._base_url + "/", f"api/ciphers/{cipher_id}/password"),
            headers=self._auth_headers(),
            json=payload,
            timeout=self._config.timeout_seconds,
        )
        response.raise_for_status()
        return response.json()


@dataclass
class CipherSelection:
    """Represents a filtered selection of ciphers."""

    items: List[Dict[str, Any]]

    def filter_collections(self, collection_ids: Iterable[str]) -> "CipherSelection":
        collection_ids = set(collection_ids)
        filtered = []
        for cipher in self.items:
            cid = cipher.get("collectionId")
            if cid and cid in collection_ids:
                filtered.append(cipher)
                continue
            multi = cipher.get("collectionIds")
            if isinstance(multi, IterableABC) and any(str(m) in collection_ids for m in multi):
                filtered.append(cipher)
        return CipherSelection(filtered)

    def filter_users(self, user_ids: Iterable[str]) -> "CipherSelection":
        user_ids = set(user_ids)
        filtered = [c for c in self.items if c.get("userId") in user_ids]
        return CipherSelection(filtered)
