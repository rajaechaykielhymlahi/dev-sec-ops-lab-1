"""
DevSecOps Lab - Session 1
Secure Flask Application (Production-Hardened Version)

Security Improvements:
- Secure session management
- Password hashing
- SQL Injection prevention
- XSS mitigation
- Command Injection prevention
- Path Traversal protection
- Secure API design
- Production-ready healthcheck
- Gunicorn-compatible database initialization
"""

# ─────────────────────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────────────────────
from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    jsonify,
    abort
)

import sqlite3
import os
import secrets
import re
import logging
from functools import wraps
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

# ─────────────────────────────────────────────────────────────
# Flask App Configuration
# ─────────────────────────────────────────────────────────────
app = Flask(__name__)

# Secure secret key from environment variable
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Secure session cookies
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ─────────────────────────────────────────────────────────────
# Logging Configuration
# ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Database Configuration
# ─────────────────────────────────────────────────────────────
DB_PATH = "secure_users.db"


def init_db():
    """
    Create database and default admin account.
    """

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    # Create default admin user
    password_hash = generate_password_hash("Admin@Secure!2024")

    c.execute(
        """
        INSERT OR IGNORE INTO users
        (id, username, password_hash, role)
        VALUES (1, 'admin', ?, 'admin')
        """,
        (password_hash,)
    )

    conn.commit()
    conn.close()


def get_db():
    """
    Open secure SQLite connection.
    """

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# IMPORTANT:
# Initialize DB when Gunicorn imports the app
with app.app_context():
    init_db()

# ─────────────────────────────────────────────────────────────
# Authentication Decorators
# ─────────────────────────────────────────────────────────────
def login_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        if "user_id" not in session:
            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated


def admin_required(f):

    @wraps(f)
    def decorated(*args, **kwargs):

        if session.get("role") != "admin":
            abort(403)

        return f(*args, **kwargs)

    return decorated


# ─────────────────────────────────────────────────────────────
# Input Validation
# ─────────────────────────────────────────────────────────────
def validate_username(username: str) -> bool:
    """
    Only allow safe usernames.
    """

    return bool(
        re.match(r"^[a-zA-Z0-9_]{3,32}$", username)
    )


# Allowlist for ping targets
ALLOWED_HOSTS = {
    "google.com",
    "example.com",
    "localhost"
}


def validate_host(host: str) -> bool:
    return host in ALLOWED_HOSTS


# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():

    return """
    <h1>Secure Flask App</h1>

    <p>DevSecOps Hardened Application</p>

    <a href='/login'>Login</a>
    """


# ─────────────────────────────────────────────────────────────
# Login Route
# Prevents SQL Injection using parameterized queries
# ─────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Input validation
        if not validate_username(username):
            return "Invalid username format", 400

        conn = get_db()

        # SECURE:
        # Parameterized query prevents SQL Injection
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        conn.close()

        # Secure password verification
        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            logger.info(f"Successful login: {username}")

            return redirect(url_for("dashboard"))

        else:

            logger.warning(
                f"Failed login attempt for: {username}"
            )

            return render_template(
                "login.html",
                error="Invalid credentials"
            ), 401

    return render_template("login.html")


# ─────────────────────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():

    return f"""
    <h1>Welcome {session['username']}!</h1>

    <p>Role: {session['role']}</p>
    """


# ─────────────────────────────────────────────────────────────
# Search Route
# Prevents XSS using Jinja2 auto-escaping
# ─────────────────────────────────────────────────────────────
@app.route("/search")
@login_required
def search():

    query = request.args.get("q", "")

    return render_template(
        "search.html",
        query=query
    )


# ─────────────────────────────────────────────────────────────
# Ping Route
# Prevents Command Injection
# ─────────────────────────────────────────────────────────────
@app.route("/ping")
@login_required
@admin_required
def ping():

    import subprocess

    host = request.args.get("host", "")

    # Allowlist validation
    if not validate_host(host):
        return jsonify({
            "error": "Host not in allowlist"
        }), 400

    # SECURE:
    # No shell=True
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=5
    )

    return jsonify({
        "output": result.stdout
    })


# ─────────────────────────────────────────────────────────────
# JSON Profile Loader
# Prevents insecure deserialization
# ─────────────────────────────────────────────────────────────
@app.route("/load_profile", methods=["POST"])
@login_required
def load_profile():

    data = request.get_json()

    if not data or not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON"
        }), 400

    # Allow only expected fields
    allowed_keys = {
        "theme",
        "language",
        "notifications"
    }

    profile = {
        k: v
        for k, v in data.items()
        if k in allowed_keys
    }

    return jsonify({
        "profile": profile
    })


# ─────────────────────────────────────────────────────────────
# File Reader
# Prevents Path Traversal
# ─────────────────────────────────────────────────────────────
@app.route("/read_file")
@login_required
def read_file():

    from werkzeug.utils import safe_join

    ALLOWED_FILES = {
        "readme.txt",
        "help.txt",
        "faq.txt"
    }

    filename = request.args.get("file", "")

    if filename not in ALLOWED_FILES:
        return "File not allowed", 403

    try:

        safe_path = safe_join(
            app.static_folder,
            "docs",
            filename
        )

        with open(safe_path, "r") as f:
            return f"<pre>{f.read()}</pre>"

    except (FileNotFoundError, OSError):
        return "File not found", 404


# ─────────────────────────────────────────────────────────────
# Secure API Endpoint
# ─────────────────────────────────────────────────────────────
@app.route("/api/users")
@login_required
@admin_required
def api_users():

    conn = get_db()

    users = conn.execute(
        "SELECT id, username, role FROM users"
    ).fetchall()

    conn.close()

    return jsonify([
        dict(u) for u in users
    ])


# ─────────────────────────────────────────────────────────────
# Docker Healthcheck Endpoint
# ─────────────────────────────────────────────────────────────
@app.route("/health")
def health():

    return jsonify({
        "status": "healthy",
        "service": "secure-flask-app"
    }), 200


# ─────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":

    # Production-safe Flask startup
    app.run(
        debug=False,
        host="0.0.0.0",
        port=8000
    )