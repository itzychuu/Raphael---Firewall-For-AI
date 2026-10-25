import hashlib
import json
import secrets
import threading
import time
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ConfirmationChallenge(BaseModel):
    token: str
    action: str
    session_id: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)
    expires_at: float
    used: bool = False


# In-memory challenge store protected by lock for thread-safe atomic consumption
_CHALLENGE_STORE: Dict[str, ConfirmationChallenge] = {}
_CHALLENGE_LOCK = threading.Lock()
DEFAULT_EXPIRY_SECONDS = 300  # 5 minutes


def canonical_action_id(action: str, parameters: Optional[Dict[str, Any]] = None) -> str:
    """Generate a deterministic, canonical representation of an action and its exact parameters.

    Binds confirmation authorization to the exact approved action and arguments, preventing
    parameter tampering, generic confirmation bypasses, and cross-action privilege escalation.
    """
    if not parameters:
        return action

    if action == "send_email":
        recipient = str(parameters.get("recipient", "")).strip()
        message = str(parameters.get("message", "")).strip()
        subject = str(parameters.get("subject", "Notification")).strip() if parameters.get("subject") else "Notification"
        norm = {"message": message, "recipient": recipient, "subject": subject}
        serialized = json.dumps(norm, sort_keys=True, separators=(",", ":"))
        param_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]
        return f"send_email:{recipient}:{param_hash}"

    if action == "file_read":
        filename = str(parameters.get("filename", "")).strip()
        norm = {"filename": filename}
        serialized = json.dumps(norm, sort_keys=True, separators=(",", ":"))
        param_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]
        return f"file_read:{filename}:{param_hash}"

    # Generic canonical representation for any other action
    cleaned = {}
    for k, v in sorted(parameters.items()):
        if isinstance(v, str):
            cleaned[k] = v.strip()
        else:
            cleaned[k] = v
    serialized = json.dumps(cleaned, sort_keys=True, separators=(",", ":"))
    param_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]
    return f"{action}:{param_hash}"


def create_confirmation_challenge(
    action: str,
    session_id: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    ttl_seconds: int = DEFAULT_EXPIRY_SECONDS,
) -> str:
    """Generate an unguessable, server-side confirmation challenge bound to action and parameters."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    challenge = ConfirmationChallenge(
        token=token,
        action=action,
        session_id=session_id,
        parameters=parameters or {},
        created_at=now,
        expires_at=now + ttl_seconds,
        used=False,
    )
    with _CHALLENGE_LOCK:
        _CHALLENGE_STORE[token] = challenge
    return token


def validate_and_consume_challenge(
    token: str,
    action: str,
    session_id: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
) -> bool:
    """Validate that the token is valid, unexpired, matches action and parameters, and consume it atomically (single-use invariant)."""
    if not token:
        return False

    with _CHALLENGE_LOCK:
        challenge = _CHALLENGE_STORE.get(token)
        if not challenge:
            return False

        # Atomic check if already consumed (single-use invariant)
        if challenge.used:
            return False

        # Check expiry
        if time.time() > challenge.expires_at:
            return False

        # Check action match
        if challenge.action != action:
            return False

        # Enforce strict session binding
        if challenge.session_id:
            if not session_id or not secrets.compare_digest(challenge.session_id, session_id):
                return False

        # Check parameters match if specified in challenge
        if challenge.parameters:
            if parameters is None:
                return False
            for k, v in challenge.parameters.items():
                if parameters.get(k) != v:
                    return False

        # Mark as consumed atomically
        challenge.used = True
        return True


def get_challenge_info(token: str) -> Optional[ConfirmationChallenge]:
    """Retrieve challenge info for inspection (returns a snapshot copy)."""
    with _CHALLENGE_LOCK:
        challenge = _CHALLENGE_STORE.get(token)
        if challenge:
            return challenge.model_copy()
        return None


def clear_confirmation_challenges() -> None:
    """Clear all challenges (used for test isolation)."""
    with _CHALLENGE_LOCK:
        _CHALLENGE_STORE.clear()
