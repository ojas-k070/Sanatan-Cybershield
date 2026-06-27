"""
Module: Chart Formatter
-----------------------
Formats vulnerability scan data into structures compatible with
Flutter's fl_chart package.  All JSON keys use camelCase to match
Dart naming conventions.

Tables used (via database.get_db):
    score_history  – id, scan_id, score, lifecycle_status, changed_by, reason, timestamp
    scans          – id, risk_score, lifecycle_status, created_at
    vulnerabilities – id, scan_id, severity, status
"""

from __future__ import annotations

from typing import Optional

from database import get_db


# ── Threshold constants (mirroring RiskClassifier levels) ────────

_THRESHOLDS = [
    {"y": 75, "label": "Critical", "color": "#FF1744"},
    {"y": 50, "label": "High",     "color": "#FF6D00"},
    {"y": 25, "label": "Medium",   "color": "#FFD600"},
]

_STATUS_ORDER = ("Safe", "Warning", "Vulnerable", "Critical", "Resolved")


def _lifecycle_status_from_score(score: int) -> str:
    """Derive a lifecycle status label from a numeric risk score."""
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "Vulnerable"
    if score >= 25:
        return "Warning"
    return "Safe"


class ChartFormatter:
    """Produces Flutter-ready chart payloads from the database."""

    # ── Score progression (line chart) ───────────────────────────

    def format_score_progression(self, scan_id: str) -> dict:
        """Return line-chart data for a scan's score history.

        Each ``score_history`` row becomes a spot on the line chart.
        ``x`` = chronological index (0, 1, 2 …), ``y`` = score.

        Args:
            scan_id: UUID of the scan to chart.

        Returns:
            A dict with ``lineChart`` and ``metadata`` keys, all in
            camelCase for direct consumption by the Flutter client.
        """
        db = get_db()
        cursor = db.execute(
            "SELECT id, score, lifecycle_status, changed_by, reason, timestamp "
            "FROM score_history "
            "WHERE scan_id = ? "
            "ORDER BY timestamp ASC",
            (scan_id,),
        )
        rows = cursor.fetchall()

        spots: list[dict] = []
        scores: list[int] = []

        for idx, row in enumerate(rows):
            score = row["score"]
            scores.append(score)
            spots.append({
                "x": idx,
                "y": score,
                "label": row["reason"] or "",
                "status": row["lifecycle_status"] or _lifecycle_status_from_score(score),
                "timestamp": row["timestamp"] or "",
            })

        current_score: int = scores[-1] if scores else 0
        current_status: str = (
            spots[-1]["status"] if spots else "Safe"
        )

        return {
            "lineChart": {
                "spots": spots,
                "thresholds": list(_THRESHOLDS),
            },
            "metadata": {
                "scanId": scan_id,
                "totalDataPoints": len(spots),
                "minScore": min(scores) if scores else 0,
                "maxScore": max(scores) if scores else 0,
                "currentScore": current_score,
                "currentStatus": current_status,
            },
        }

    # ── Dashboard summary ────────────────────────────────────────

    def format_dashboard_summary(self, user_id: Optional[str] = None) -> dict:
        """Aggregate high-level scan statistics for the dashboard.

        Args:
            user_id: If provided, only scans belonging to this user
                     are included (requires a ``user_id`` column on
                     the ``scans`` table).  When ``None`` all scans
                     are aggregated.

        Returns:
            A camelCase dict containing totals, breakdowns by status
            and severity, and a list of recent scans.
        """
        db = get_db()

        # ----- base query fragments --------------------------------
        where_clause = ""
        params: tuple = ()
        if user_id is not None:
            where_clause = "WHERE user_id = ?"
            params = (user_id,)

        # 1. Total / active / resolved counts
        row = db.execute(
            f"SELECT COUNT(*) AS total, "
            f"  SUM(CASE WHEN lifecycle_status != 'Resolved' THEN 1 ELSE 0 END) AS active, "
            f"  SUM(CASE WHEN lifecycle_status  = 'Resolved' THEN 1 ELSE 0 END) AS resolved, "
            f"  AVG(risk_score) AS avg_score "
            f"FROM scans {where_clause}",
            params,
        ).fetchone()

        total_scans: int = row["total"] or 0
        active_scans: int = row["active"] or 0
        resolved_scans: int = row["resolved"] or 0
        average_score: int = int(row["avg_score"]) if row["avg_score"] is not None else 0

        # 2. Status breakdown
        status_rows = db.execute(
            f"SELECT lifecycle_status, COUNT(*) AS cnt "
            f"FROM scans {where_clause} "
            f"GROUP BY lifecycle_status",
            params,
        ).fetchall()
        status_breakdown: dict[str, int] = {s: 0 for s in _STATUS_ORDER}
        for sr in status_rows:
            status_breakdown[sr["lifecycle_status"]] = sr["cnt"]

        # 3. Severity breakdown (across all vulnerabilities)
        if user_id is not None:
            sev_rows = db.execute(
                "SELECT v.severity, COUNT(*) AS cnt "
                "FROM vulnerabilities v "
                "INNER JOIN scans s ON v.scan_id = s.id "
                "WHERE s.user_id = ? "
                "GROUP BY v.severity",
                (user_id,),
            ).fetchall()
        else:
            sev_rows = db.execute(
                "SELECT severity, COUNT(*) AS cnt "
                "FROM vulnerabilities "
                "GROUP BY severity",
            ).fetchall()

        severity_breakdown: dict[str, int] = {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0,
        }
        for sv in sev_rows:
            if sv["severity"] in severity_breakdown:
                severity_breakdown[sv["severity"]] = sv["cnt"]

        # 4. Recent scans (last 10)
        recent_rows = db.execute(
            f"SELECT id, file_path, risk_score, lifecycle_status, created_at "
            f"FROM scans {where_clause} "
            f"ORDER BY created_at DESC LIMIT 10",
            params,
        ).fetchall()

        recent_scans: list[dict] = [
            {
                "id": r["id"],
                "filePath": r["file_path"],
                "riskScore": r["risk_score"],
                "lifecycleStatus": r["lifecycle_status"],
                "createdAt": r["created_at"],
            }
            for r in recent_rows
        ]

        return {
            "totalScans": total_scans,
            "activeScans": active_scans,
            "resolvedScans": resolved_scans,
            "averageScore": average_score,
            "statusBreakdown": status_breakdown,
            "severityBreakdown": severity_breakdown,
            "recentScans": recent_scans,
        }
