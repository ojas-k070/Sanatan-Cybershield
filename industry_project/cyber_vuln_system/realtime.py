"""
Module: Real-time Event System
------------------------------
Provides WebSocket broadcasting via Flask-SocketIO so the Flutter
client receives instant updates for score changes, lifecycle
transitions, audit logs, scan completions, and vulnerability
status changes.

Usage:
    from realtime import init_socketio, emit_event

    # During app setup
    socketio = init_socketio(app)

    # Anywhere in the codebase
    emit_event("scan_completed", {"scanId": "...", "riskScore": 42})

Supported event names:
    score_updated
    lifecycle_changed
    audit_log_created
    scan_completed
    vulnerability_status_changed
"""

from __future__ import annotations

from flask_socketio import SocketIO, emit

# Module-level instance — set once by init_socketio(), then shared
# across the application via import.
_socketio: SocketIO | None = None


def init_socketio(app) -> SocketIO:
    """Create, configure, and return the global SocketIO instance.

    Args:
        app: The Flask application instance.

    Returns:
        The initialised ``SocketIO`` object (also stored at module
        level so :func:`emit_event` can use it).
    """
    global _socketio
    _socketio = SocketIO(app, cors_allowed_origins="*")

    # ── Connection lifecycle handlers ──────────────────────────
    @_socketio.on("connect")
    def _handle_connect() -> None:
        print("[WebSocket] Client connected")

    @_socketio.on("disconnect")
    def _handle_disconnect() -> None:
        print("[WebSocket] Client disconnected")

    return _socketio


def emit_event(event_name: str, data: dict) -> None:
    """Broadcast an event to every connected WebSocket client.

    If the SocketIO instance has not been initialised yet (i.e.
    ``init_socketio`` was never called), the call is silently
    ignored so that non-WebSocket tests and scripts still work.

    Args:
        event_name: One of the supported event names
                    (``score_updated``, ``lifecycle_changed``, etc.).
        data:       Arbitrary JSON-serialisable payload.
    """
    if _socketio is None:
        print(f"[WebSocket] socketio not initialised — dropping '{event_name}'")
        return

    _socketio.emit(event_name, data)
