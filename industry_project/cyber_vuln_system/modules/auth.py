"""
JWT authentication module for the Cybersecurity Vulnerability Analysis system.

Handles user registration, login, token generation / verification,
and Flask route-level authorization decorators.
"""

import os
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from typing import Any, Callable, Dict, Optional

import jwt
from flask import g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from database import get_db

SECRET_KEY: str = os.environ.get(
    "CYBER_VULN_SECRET_KEY", "cyber-vuln-secret-key-change-in-production"
)
TOKEN_EXPIRY: timedelta = timedelta(hours=24)


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------

def _row_to_user_dict(row) -> Dict[str, Any]:
    """Convert a sqlite3.Row for the users table into a plain dict,
    omitting the password_hash field."""
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "createdAt": row["created_at"],
    }


def register_user(
    username: str, password: str, role: str = "user"
) -> Dict[str, Any]:
    """Register a new user and return a user dict (without password_hash).

    Raises ``sqlite3.IntegrityError`` if the username already exists.
    """
    db = get_db()
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    db.execute(
        "INSERT INTO users (id, username, password_hash, role, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (user_id, username, generate_password_hash(password), role, now),
    )
    db.commit()

    return {
        "id": user_id,
        "username": username,
        "role": role,
        "createdAt": now,
    }


def update_user_profile(
    user_id: str,
    new_username: Optional[str] = None,
    new_password: Optional[str] = None,
) -> Dict[str, Any]:
    """Update username and/or password for an existing user.

    Returns the updated user dict.
    Raises ``ValueError`` on validation failures.
    """
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        raise ValueError("User not found")

    if new_username and new_username != row["username"]:
        existing = db.execute(
            "SELECT id FROM users WHERE username = ? AND id != ?",
            (new_username, user_id),
        ).fetchone()
        if existing:
            raise ValueError("Username already taken")
        db.execute(
            "UPDATE users SET username = ? WHERE id = ?",
            (new_username, user_id),
        )

    if new_password:
        if len(new_password) < 4:
            raise ValueError("Password must be at least 4 characters")
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )

    db.commit()

    updated = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _row_to_user_dict(updated)


# ---------------------------------------------------------------------------
# Authentication & token management
# ---------------------------------------------------------------------------

def authenticate(username: str, password: str) -> Optional[str]:
    """Verify credentials and return a signed JWT token string, or ``None``."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if row is None or not check_password_hash(row["password_hash"], password):
        return None

    payload = {
        "user_id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "exp": datetime.now(timezone.utc) + TOKEN_EXPIRY,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and verify a JWT token.

    Returns a user dict (id, username, role) on success, or ``None``
    if the token is invalid or expired.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return {
            "id": payload["user_id"],
            "username": payload["username"],
            "role": payload["role"],
        }
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# ---------------------------------------------------------------------------
# Flask decorators
# ---------------------------------------------------------------------------

def require_auth(f: Callable) -> Callable:
    """Decorator that enforces a valid ``Authorization: Bearer <token>`` header.

    On success the decoded user dict is stored in ``flask.g.current_user``.
    """

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid authorization header"}), 401

        token = auth_header.split(" ", 1)[1]
        user = verify_token(token)

        if user is None:
            return jsonify({"error": "Invalid or expired token"}), 401

        g.current_user = user
        return f(*args, **kwargs)

    return decorated


def require_admin(f: Callable) -> Callable:
    """Decorator that enforces admin-level access.

    Must be applied *after* (i.e. below) ``@require_auth`` so that
    ``g.current_user`` is already populated.
    """

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid authorization header"}), 401

        token = auth_header.split(" ", 1)[1]
        user = verify_token(token)

        if user is None:
            return jsonify({"error": "Invalid or expired token"}), 401

        if user.get("role") != "admin":
            return jsonify({"error": "Admin privileges required"}), 403

        g.current_user = user
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def create_default_admin() -> None:
    """Create an ``admin`` user with password ``admin123`` when the users
    table is empty.  Intended to be called once during application init."""
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    if count == 0:
        register_user("admin", "admin123", role="admin")
