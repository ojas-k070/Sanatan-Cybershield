"""Audit log system for cybersecurity vulnerability analysis.

Provides structured audit logging for all scan-related actions,
with support for pagination and filtering.
"""

from __future__ import annotations

import math
import uuid
from datetime import datetime
from typing import Any, Optional

from database import get_db


class AuditLogger:
    """Records and retrieves audit log entries for scan actions."""

    def log_action(
        self,
        scan_id: str,
        action: str,
        performed_by: str,
        role: str = "system",
        old_score: Optional[int] = None,
        new_score: Optional[int] = None,
        old_status: Optional[str] = None,
        new_status: Optional[str] = None,
        vulnerability_status: Optional[str] = None,
        severity_level: Optional[str] = None,
        details: Optional[str] = None,
    ) -> dict[str, Any]:
        """Insert a new entry into the audit_logs table.

        Args:
            scan_id: Identifier of the scan being audited.
            action: Description of the action performed.
            performed_by: Identity of the actor.
            role: Role of the actor (default ``'system'``).
            old_score: Previous risk score, if applicable.
            new_score: Updated risk score, if applicable.
            old_status: Previous lifecycle status, if applicable.
            new_status: Updated lifecycle status, if applicable.
            vulnerability_status: Current vulnerability status descriptor.
            severity_level: Severity level descriptor.
            details: Free-text details about the action.

        Returns:
            The created log entry as a dictionary.
        """

        timestamp = datetime.utcnow().isoformat() + "Z"

        db = get_db()
        cursor = db.execute(
            """
            INSERT INTO audit_logs
                (scan_id, action, performed_by, role,
                 old_score, new_score, old_status, new_status,
                 vulnerability_status, severity_level, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                action,
                performed_by,
                role,
                old_score,
                new_score,
                old_status,
                new_status,
                vulnerability_status,
                severity_level,
                details,
                timestamp,
            ),
        )
        db.commit()
        log_id = cursor.lastrowid

        return {
            "id": log_id,
            "scanId": scan_id,
            "action": action,
            "performedBy": performed_by,
            "role": role,
            "oldScore": old_score,
            "newScore": new_score,
            "oldStatus": old_status,
            "newStatus": new_status,
            "vulnerabilityStatus": vulnerability_status,
            "severityLevel": severity_level,
            "details": details,
            "timestamp": timestamp,
        }

    def get_logs(
        self,
        scan_id: Optional[str] = None,
        action: Optional[str] = None,
        performed_by: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        """Return paginated, optionally filtered audit log entries.

        Args:
            scan_id: Filter by scan identifier.
            action: Filter by action string.
            performed_by: Filter by actor identity.
            page: Page number (1-indexed, default ``1``).
            per_page: Items per page (default ``20``).

        Returns:
            Dictionary with keys ``items``, ``total``, ``page``,
            ``perPage``, and ``totalPages``.
        """

        db = get_db()

        conditions: list[str] = []
        params: list[Any] = []

        if scan_id is not None:
            conditions.append("a.scan_id = ?")
            params.append(scan_id)
        if action is not None:
            conditions.append("a.action = ?")
            params.append(action)
        if performed_by is not None:
            conditions.append("a.performed_by = ?")
            params.append(performed_by)

        where_clause = (" WHERE " + " AND ".join(conditions)) if conditions else ""

        # Total count
        count_row = db.execute(
            f"SELECT COUNT(*) AS cnt FROM audit_logs a{where_clause}", params
        ).fetchone()
        total: int = count_row["cnt"] if count_row else 0

        total_pages = max(1, math.ceil(total / per_page))

        # Paginated rows with username JOIN
        offset = (page - 1) * per_page
        rows = db.execute(
            f"SELECT a.*, u.username as performer_name FROM audit_logs a "
            f"LEFT JOIN users u ON a.performed_by = u.id"
            f"{' WHERE ' + ' AND '.join(conditions) if conditions else ''} "
            f"ORDER BY a.timestamp DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()

        items = [self._row_to_dict(row) for row in rows]

        return {
            "items": items,
            "total": total,
            "page": page,
            "perPage": per_page,
            "totalPages": total_pages,
        }

    def get_scan_logs(self, scan_id: str) -> list[dict[str, Any]]:
        """Return all audit log entries for a given scan, oldest first.

        Args:
            scan_id: Identifier of the scan.

        Returns:
            List of log entry dictionaries ordered by timestamp ascending.
        """

        db = get_db()
        rows = db.execute(
            "SELECT * FROM audit_logs WHERE scan_id = ? ORDER BY timestamp ASC",
            (scan_id,),
        ).fetchall()

        return [self._row_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row) -> dict[str, Any]:
        """Convert a ``sqlite3.Row`` to a camelCase dictionary."""

        d = {
            "id": row["id"],
            "scanId": row["scan_id"],
            "action": row["action"],
            "performedBy": row["performed_by"],
            "role": row["role"],
            "oldScore": row["old_score"],
            "newScore": row["new_score"],
            "oldStatus": row["old_status"],
            "newStatus": row["new_status"],
            "vulnerabilityStatus": row["vulnerability_status"],
            "severityLevel": row["severity_level"],
            "details": row["details"],
            "timestamp": row["timestamp"],
        }
        # Include performer username when available (from JOIN)
        try:
            d["performerName"] = row["performer_name"]
        except (IndexError, KeyError):
            d["performerName"] = None
        return d
