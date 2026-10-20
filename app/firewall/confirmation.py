import secrets
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


# In-memory challenge store: token -> ConfirmationChallenge
_CHALLENGE_STORE: Dict[str, ConfirmationChallenge] = {}
DEFAULT_EXPIRY_SECONDS = 300  # 5 minutes


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
    _CHALLENGE_STORE[token] = challenge
    return token


def validate_and_consume_challenge(
    token: str,
    action: str,
    session_id: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
) -> bool:
    """Validate that the token is valid, unexpired, matches action and parameters, and consume it (single-use)."""
    if not token or token not in _CHALLENGE_STORE:
        return False

    challenge = _CHALLENGE_STORE[token]

    # Check if already consumed (single-use invariant)
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

    # Mark as consumed immediately
    challenge.used = True
    return True


def get_challenge_info(token: str) -> Optional[ConfirmationChallenge]:
    """Retrieve challenge info for inspection."""
    return _CHALLENGE_STORE.get(token)


def clear_confirmation_challenges() -> None:
    """Clear all challenges (used for test isolation)."""
    _CHALLENGE_STORE.clear()
