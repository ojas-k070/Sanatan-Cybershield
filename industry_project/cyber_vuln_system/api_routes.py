"""
API v2 Routes — Flutter-Compatible REST Endpoints
===================================================
Flask Blueprint providing JWT-protected endpoints for:
  - Authentication (register, login, profile)
  - Scan management (create, list, detail, delete)
  - Lifecycle transitions and score history
  - Vulnerability status tracking
  - Audit logs (paginated, filterable)
  - Chart data formatted for fl_chart

All responses follow the standard envelope::

    {
        "success": true/false,
        "data": { ... },
        "message": "...",
        "timestamp": "..."
    }
"""

import os
import uuid
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, g, jsonify, request

from database import get_db
from modules.auth import (
    authenticate,
    create_default_admin,
    register_user,
    require_admin,
    require_auth,
    update_user_profile,
    verify_token,
)
from modules.audit_logger import AuditLogger
from modules.chart_formatter import ChartFormatter
from modules.lifecycle_manager import LifecycleManager
from modules.scan_service import ScanService
from realtime import emit_event

api = Blueprint("api_v2", __name__, url_prefix="/api/v2")

# Shared service instances (lazy-initialized to avoid import-time errors
# when API keys like OPENROUTER_API_KEY aren't set yet)
_scan_service = None
lifecycle_manager = LifecycleManager()
audit_logger = AuditLogger()
chart_formatter = ChartFormatter()


def get_scan_service():
    """Lazy-initialize ScanService (requires API keys at runtime)."""
    global _scan_service
    if _scan_service is None:
        _scan_service = ScanService()
    return _scan_service


# ──────────────────────────────────────────────────────────
#  Response helpers
# ──────────────────────────────────────────────────────────

def _ok(data=None, message="Success", status=200, **extra):
    body = {
        "success": True,
        "data": data,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    body.update(extra)
    return jsonify(body), status


def _error(message, status=400):
    return jsonify({
        "success": False,
        "data": None,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), status


# ══════════════════════════════════════════════════════════
#  AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════

@api.route("/auth/register", methods=["POST"])
def api_register():
    """Register a new user account."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "user")

    if not username or not password:
        return _error("Username and password are required")

    if len(password) < 4:
        return _error("Password must be at least 4 characters")

    try:
        user = register_user(username, password, role)
        token = authenticate(username, password)
        return _ok({"user": user, "token": token}, "Registration successful", 201)
    except Exception as e:
        return _error(f"Registration failed: {str(e)}")


@api.route("/auth/login", methods=["POST"])
def api_login():
    """Authenticate and receive a JWT token."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return _error("Username and password are required")

    token = authenticate(username, password)
    if token is None:
        return _error("Invalid credentials", 401)

    user = verify_token(token)
    return _ok({"token": token, "user": user}, "Login successful")


@api.route("/auth/me", methods=["GET"])
@require_auth
def api_me():
    """Get the current authenticated user's profile."""
    return _ok(g.current_user, "Profile retrieved")


@api.route("/auth/profile", methods=["PUT"])
@require_auth
def api_update_profile():
    """Update username and/or password for the current user."""
    data = request.get_json(silent=True) or {}
    new_username = data.get("username", "").strip() or None
    new_password = data.get("password") or None

    if not new_username and not new_password:
        return _error("Provide username or password to update")

    try:
        updated = update_user_profile(
            g.current_user["id"], new_username, new_password
        )
        # Re-generate token with new username
        token = authenticate(updated["username"], data.get("password", ""))
        return _ok({"user": updated, "token": token}, "Profile updated")
    except ValueError as e:
        return _error(str(e))
    except Exception as e:
        return _error(f"Update failed: {str(e)}")


# ══════════════════════════════════════════════════════════
#  SCAN ENDPOINTS
# ══════════════════════════════════════════════════════════

@api.route("/scan", methods=["POST"])
@require_auth
def api_create_scan():
    """Run a new vulnerability scan."""
    user_id = g.current_user["id"]

    # Handle both JSON and form-data
    if request.is_json:
        data = request.get_json()
        mode = data.get("mode", "paste")
    else:
        data = request.form
        mode = data.get("mode", "paste")

    try:
        if mode == "paste":
            source_code = data.get("code", "")
            if not source_code:
                return _error("Code is required for paste mode")

            language = get_scan_service().detect_language(source_code)
            temp_path = os.path.join(
                "sample_code", f"paste_{uuid.uuid4().hex[:6]}.py"
            )
            os.makedirs("sample_code", exist_ok=True)
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(source_code)

            result = get_scan_service().run_scan(
                source_code, temp_path, language, mode, user_id
            )

        elif mode == "upload":
            file = request.files.get("file")
            if not file:
                return _error("No file uploaded")

            temp_path = os.path.join(
                "sample_code",
                f"up_{uuid.uuid4().hex[:6]}_{file.filename}",
            )
            os.makedirs("sample_code", exist_ok=True)
            file.save(temp_path)

            with open(temp_path, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()

            language = get_scan_service().detect_language(source_code)
            result = get_scan_service().run_scan(
                source_code, temp_path, language, mode, user_id
            )

        elif mode == "github":
            repo_url = data.get("github_url") or data.get("repo_url")
            if not repo_url:
                return _error("GitHub URL is required")

            result = get_scan_service().run_repo_scan(repo_url, user_id)

        else:
            return _error(f"Invalid mode: {mode}")

        # Emit real-time event
        emit_event("scan_completed", result)
        return _ok(result, "Scan completed successfully", 201)

    except Exception as e:
        return _error(f"Scan failed: {str(e)}", 500)


@api.route("/scans", methods=["GET"])
@require_auth
def api_list_scans():
    """List scans for the current user (paginated)."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    user_id = g.current_user["id"]

    # Admins can see all scans
    if g.current_user.get("role") == "admin":
        user_id = request.args.get("user_id", None)

    result = get_scan_service().get_scans(user_id=user_id, page=page, per_page=per_page)
    return _ok(result["scans"], "Scans retrieved", pagination=result["pagination"])


@api.route("/scans/<scan_id>", methods=["GET"])
@require_auth
def api_get_scan(scan_id):
    """Get detailed scan results including vulnerabilities."""
    try:
        scan = get_scan_service().get_scan(scan_id)
        return _ok(scan, "Scan details retrieved")
    except ValueError as e:
        return _error(str(e), 404)


@api.route("/scans/<scan_id>", methods=["DELETE"])
@require_admin
def api_delete_scan(scan_id):
    """Delete a scan and its related data (admin only)."""
    db = get_db()
    try:
        db.execute("DELETE FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
        db.execute("DELETE FROM score_history WHERE scan_id = ?", (scan_id,))
        db.execute("DELETE FROM audit_logs WHERE scan_id = ?", (scan_id,))
        db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        db.commit()

        audit_logger.log_action(
            scan_id=scan_id,
            action="scan_deleted",
            performed_by=g.current_user["id"],
            role="admin",
            details=f"Scan {scan_id} deleted by admin",
        )
        return _ok(None, "Scan deleted successfully")
    except Exception as e:
        return _error(f"Delete failed: {str(e)}", 500)


# ══════════════════════════════════════════════════════════
#  LIFECYCLE & SCORE ENDPOINTS
# ══════════════════════════════════════════════════════════

@api.route("/scans/<scan_id>/lifecycle", methods=["GET"])
@require_auth
def api_get_lifecycle(scan_id):
    """Get lifecycle transition history for a scan."""
    try:
        history = lifecycle_manager.get_lifecycle_history(scan_id)
        return _ok(history, "Lifecycle history retrieved")
    except Exception as e:
        return _error(str(e), 500)


@api.route("/scans/<scan_id>/lifecycle", methods=["PUT"])
@require_admin
def api_transition_lifecycle(scan_id):
    """Manually transition the lifecycle state (admin only)."""
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "").strip()

    if not new_status:
        return _error("Target status is required")

    valid_statuses = {"Safe", "Warning", "Vulnerable", "Critical", "Resolved"}
    if new_status not in valid_statuses:
        return _error(f"Invalid status. Must be one of: {', '.join(valid_statuses)}")

    try:
        result = lifecycle_manager.transition(
            scan_id, new_status,
            performed_by=g.current_user["id"],
            role="admin",
        )
        emit_event("lifecycle_changed", result)
        return _ok(result, f"Lifecycle transitioned to {new_status}")
    except ValueError as e:
        return _error(str(e), 400)


@api.route("/scans/<scan_id>/resolve", methods=["PUT"])
@require_admin
def api_resolve_scan(scan_id):
    """Resolve a scan — resets score to 0 (admin only)."""
    try:
        result = lifecycle_manager.transition(
            scan_id, "Resolved",
            performed_by=g.current_user["id"],
            role="admin",
        )
        emit_event("lifecycle_changed", result)
        return _ok(result, "Scan resolved — score reset to 0")
    except ValueError as e:
        return _error(str(e), 400)


@api.route("/scans/<scan_id>/score-history", methods=["GET"])
@require_auth
def api_score_history(scan_id):
    """Get score change history for a scan."""
    try:
        history = lifecycle_manager.get_lifecycle_history(scan_id)
        return _ok(history, "Score history retrieved")
    except Exception as e:
        return _error(str(e), 500)


@api.route("/scans/<scan_id>/score", methods=["PUT"])
@require_admin
def api_update_score(scan_id):
    """Manual score override (admin only)."""
    data = request.get_json(silent=True) or {}
    new_score = data.get("score")

    if new_score is None or not isinstance(new_score, int) or new_score < 0 or new_score > 100:
        return _error("Score must be an integer between 0 and 100")

    db = get_db()
    now = datetime.now(timezone.utc).isoformat()

    row = db.execute(
        "SELECT risk_score, lifecycle_status FROM scans WHERE id = ?",
        (scan_id,),
    ).fetchone()

    if not row:
        return _error("Scan not found", 404)

    old_score = row["risk_score"]
    old_status = row["lifecycle_status"]

    # Determine new lifecycle from score
    if new_score == 0:
        new_status = "Resolved"
    elif new_score <= 24:
        new_status = "Warning"
    elif new_score <= 49:
        new_status = "Vulnerable"
    else:
        new_status = "Critical"

    db.execute(
        "UPDATE scans SET risk_score = ?, lifecycle_status = ?, updated_at = ? WHERE id = ?",
        (new_score, new_status, now, scan_id),
    )
    db.execute(
        "INSERT INTO score_history (scan_id, score, lifecycle_status, changed_by, reason, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, new_score, new_status, g.current_user["id"], "Manual score override", now),
    )
    db.commit()

    audit_logger.log_action(
        scan_id=scan_id,
        action="manual_score_override",
        performed_by=g.current_user["id"],
        role="admin",
        old_score=old_score,
        new_score=new_score,
        old_status=old_status,
        new_status=new_status,
        details=f"Score manually changed from {old_score} to {new_score}",
    )

    result = {
        "scanId": scan_id,
        "oldScore": old_score,
        "newScore": new_score,
        "oldStatus": old_status,
        "newStatus": new_status,
        "timestamp": now,
    }
    emit_event("score_updated", result)
    return _ok(result, "Score updated successfully")


# ══════════════════════════════════════════════════════════
#  VULNERABILITY ENDPOINTS
# ══════════════════════════════════════════════════════════

@api.route("/scans/<scan_id>/vulnerabilities", methods=["GET"])
@require_auth
def api_get_vulnerabilities(scan_id):
    """List vulnerabilities for a scan."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity, created_at",
        (scan_id,),
    ).fetchall()

    vulns = [{
        "id": r["id"],
        "scanId": r["scan_id"],
        "vulnId": r["vuln_id"],
        "category": r["category"],
        "severity": r["severity"],
        "lineNumber": r["line_number"],
        "lineContent": r["line_content"],
        "status": r["status"],
        "cweId": r["cwe_id"],
        "owaspCategory": r["owasp_category"],
        "recommendation": r["recommendation"],
        "aiExplanation": r["ai_explanation"],
        "createdAt": r["created_at"],
    } for r in rows]

    return _ok(vulns, f"{len(vulns)} vulnerabilities found")


@api.route("/vulnerabilities/<vuln_id>/status", methods=["PUT"])
@require_admin
def api_update_vulnerability_status(vuln_id):
    """Update a vulnerability's status (admin only)."""
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "").strip()

    valid = {"open", "mitigated", "resolved", "fixed", "accepted"}
    if new_status not in valid:
        return _error(f"Invalid status. Must be one of: {', '.join(valid)}")

    try:
        result = get_scan_service().update_vulnerability_status(
            vuln_id, new_status, g.current_user["id"],
        )
        emit_event("vulnerability_status_changed", result)
        return _ok(result, f"Vulnerability status updated to {new_status}")
    except ValueError as e:
        return _error(str(e), 404)


# ══════════════════════════════════════════════════════════
#  AUDIT LOG ENDPOINTS
# ══════════════════════════════════════════════════════════

@api.route("/audit-logs", methods=["GET"])
@require_auth
def api_all_audit_logs():
    """Get audit logs (paginated). Admins see all, users see their own."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    action_filter = request.args.get("action")
    user_filter = request.args.get("performed_by")

    # Non-admins only see logs for their own actions
    if g.current_user.get("role") != "admin":
        user_filter = g.current_user["id"]

    result = audit_logger.get_logs(
        action=action_filter,
        performed_by=user_filter,
        page=page,
        per_page=per_page,
    )
    return _ok(result["items"], "Audit logs retrieved", pagination={
        "page": result["page"],
        "perPage": result["perPage"],
        "total": result["total"],
        "totalPages": result["totalPages"],
    })


@api.route("/scans/<scan_id>/audit-logs", methods=["GET"])
@require_auth
def api_scan_audit_logs(scan_id):
    """Get audit logs for a specific scan."""
    logs = audit_logger.get_scan_logs(scan_id)
    return _ok(logs, f"{len(logs)} audit log entries found")


# ══════════════════════════════════════════════════════════
#  CHART DATA ENDPOINTS (fl_chart compatible)
# ══════════════════════════════════════════════════════════

@api.route("/scans/<scan_id>/chart-data", methods=["GET"])
@require_auth
def api_chart_data(scan_id):
    """Get score progression data formatted for fl_chart."""
    try:
        data = chart_formatter.format_score_progression(scan_id)
        return _ok(data, "Chart data retrieved")
    except Exception as e:
        return _error(str(e), 500)


@api.route("/dashboard/summary", methods=["GET"])
@require_auth
def api_dashboard_summary():
    """Get aggregate dashboard statistics."""
    user_id = g.current_user["id"]
    # Admins see all data
    if g.current_user.get("role") == "admin":
        user_id = None

    try:
        data = chart_formatter.format_dashboard_summary(user_id)
        return _ok(data, "Dashboard summary retrieved")
    except Exception as e:
        return _error(str(e), 500)
