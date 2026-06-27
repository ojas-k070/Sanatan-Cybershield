"""Cyber safety score lifecycle state machine.

Manages lifecycle status transitions for vulnerability scans,
enforces valid transition rules, and records full history.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from database import get_db


# ------------------------------------------------------------------
# Enum & helper
# ------------------------------------------------------------------

class LifecycleStatus(enum.Enum):
    """Possible lifecycle states for a vulnerability scan."""

    SAFE = "Safe"
    WARNING = "Warning"
    VULNERABLE = "Vulnerable"
    CRITICAL = "Critical"
    RESOLVED = "Resolved"


def score_to_lifecycle(score: int) -> LifecycleStatus:
    """Map a numeric risk score to a lifecycle status.

    Args:
        score: Non-negative integer risk score.

    Returns:
        Corresponding ``LifecycleStatus``.

    Mapping:
        - ``0``      → Safe
        - ``1–24``   → Warning
        - ``25–49``  → Vulnerable
        - ``50+``    → Critical
    """

    if score <= 0:
        return LifecycleStatus.SAFE
    if score <= 24:
        return LifecycleStatus.WARNING
    if score <= 49:
        return LifecycleStatus.VULNERABLE
    return LifecycleStatus.CRITICAL


# ------------------------------------------------------------------
# Allowed transitions
# ------------------------------------------------------------------

_VALID_TRANSITIONS: dict[str, set[str]] = {
    "Safe": {"Warning", "Resolved"},
    "Warning": {"Safe", "Vulnerable", "Resolved"},
    "Vulnerable": {"Warning", "Critical", "Resolved"},
    "Critical": {"Vulnerable", "Resolved"},
    "Resolved": set(),
}


# ------------------------------------------------------------------
# Manager
# ------------------------------------------------------------------

class LifecycleManager:
    """Orchestrates lifecycle status transitions for scans."""

    def determine_initial_status(self, risk_score: int) -> str:
        """Return the lifecycle status string for an initial risk score.

        Args:
            risk_score: Non-negative integer risk score.

        Returns:
            The ``value`` of the matching ``LifecycleStatus``.
        """

        return score_to_lifecycle(risk_score).value

    def can_transition(self, current: str, target: str) -> bool:
        """Check whether a transition from *current* to *target* is allowed.

        Args:
            current: Current lifecycle status value.
            target: Desired lifecycle status value.

        Returns:
            ``True`` if the transition is permitted, ``False`` otherwise.
        """

        allowed = _VALID_TRANSITIONS.get(current)
        if allowed is None:
            return False
        return target in allowed

    def transition(
        self,
        scan_id: str,
        new_status: str,
        performed_by: str,
        role: str = "system",
    ) -> dict[str, Any]:
        """Execute a lifecycle transition for a scan.

        Updates the ``scans`` table, appends to ``score_history``, and
        writes an ``audit_logs`` entry.

        Args:
            scan_id: Identifier of the scan to transition.
            new_status: Target lifecycle status value.
            performed_by: Identity of the actor requesting the transition.
            role: Role of the actor (default ``'system'``).

        Returns:
            Dictionary with ``scanId``, ``oldStatus``, ``newStatus``,
            ``oldScore``, ``newScore``, and ``timestamp``.

        Raises:
            ValueError: If the scan does not exist or the transition is
                not permitted.
        """

        db = get_db()
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Fetch current scan state
        row = db.execute(
            "SELECT lifecycle_status, risk_score FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

        if row is None:
            raise ValueError(f"Scan {scan_id} not found")

        old_status: str = row["lifecycle_status"]
        old_score: int = row["risk_score"]

        if not self.can_transition(old_status, new_status):
            raise ValueError(
                f"Transition from '{old_status}' to '{new_status}' is not allowed"
            )

        # Determine new score
        new_score = 0 if new_status == LifecycleStatus.RESOLVED.value else old_score

        # Update scans table
        db.execute(
            "UPDATE scans SET lifecycle_status = ?, risk_score = ?, updated_at = ? WHERE id = ?",
            (new_status, new_score, timestamp, scan_id),
        )

        # Insert score_history entry
        db.execute(
            """
            INSERT INTO score_history
                (scan_id, score, lifecycle_status, changed_by, reason, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                new_score,
                new_status,
                performed_by,
                f"Transition from {old_status} to {new_status}",
                timestamp,
            ),
        )

        # Insert audit_logs entry
        db.execute(
            """
            INSERT INTO audit_logs
                (scan_id, action, performed_by, role,
                 old_score, new_score, old_status, new_status,
                 vulnerability_status, severity_level, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                "lifecycle_transition",
                performed_by,
                role,
                old_score,
                new_score,
                old_status,
                new_status,
                new_status,
                new_status,
                f"Lifecycle transitioned from {old_status} to {new_status}",
                timestamp,
            ),
        )

        db.commit()

        return {
            "scanId": scan_id,
            "oldStatus": old_status,
            "newStatus": new_status,
            "oldScore": old_score,
            "newScore": new_score,
            "timestamp": timestamp,
        }

    def get_lifecycle_history(self, scan_id: str) -> list[dict[str, Any]]:
        """Return the full score history for a scan.

        Args:
            scan_id: Identifier of the scan.

        Returns:
            List of history entry dictionaries ordered by timestamp ascending.
        """

        db = get_db()
        rows = db.execute(
            "SELECT * FROM score_history WHERE scan_id = ? ORDER BY timestamp ASC",
            (scan_id,),
        ).fetchall()

        return [
            {
                "id": row["id"],
                "scanId": row["scan_id"],
                "score": row["score"],
                "lifecycleStatus": row["lifecycle_status"],
                "changedBy": row["changed_by"],
                "reason": row["reason"],
                "timestamp": row["timestamp"],
            }
            for row in rows
        ]
