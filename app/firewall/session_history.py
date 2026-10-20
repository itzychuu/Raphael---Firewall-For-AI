import threading
from collections import OrderedDict, deque
from typing import Dict, List, Optional
from app.firewall.behavior_models import BehavioralEvent

MAX_EVENTS_PER_SESSION = 50
MAX_SESSIONS = 500


class SessionHistoryManager:
    """Thread-safe, bounded, in-memory session history manager.
    Maintains chronological order and enforces strict session isolation.
    """

    def __init__(self, max_events_per_session: int = MAX_EVENTS_PER_SESSION, max_sessions: int = MAX_SESSIONS):
        self._max_events = max_events_per_session
        self._max_sessions = max_sessions
        self._lock = threading.Lock()
        self._sessions: OrderedDict[str, deque[BehavioralEvent]] = OrderedDict()

    def add_event(self, event: BehavioralEvent) -> None:
        """Append an event to the specified session, evicting oldest events or sessions if bounded limits are exceeded."""
        with self._lock:
            session_id = event.session_id
            if session_id in self._sessions:
                # Mark as recently used
                self._sessions.move_to_end(session_id)
            else:
                if len(self._sessions) >= self._max_sessions:
                    # Evict the oldest inactive session
                    self._sessions.popitem(last=False)
                self._sessions[session_id] = deque(maxlen=self._max_events)

            self._sessions[session_id].append(event)

    def get_session_events(self, session_id: str) -> List[BehavioralEvent]:
        """Retrieve a copy of events for the specified session in chronological order."""
        with self._lock:
            if session_id not in self._sessions:
                return []
            self._sessions.move_to_end(session_id)
            return list(self._sessions[session_id])

    def clear_session(self, session_id: str) -> bool:
        """Remove a specific session's history."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def clear_all(self) -> None:
        """Clear all active session histories (useful for test resets)."""
        with self._lock:
            self._sessions.clear()

    def get_session_count(self) -> int:
        """Return the number of active tracked sessions."""
        with self._lock:
            return len(self._sessions)


# Global session history manager instance
session_history = SessionHistoryManager()
