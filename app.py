import os
import re
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, session, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# =============================================================================
# APP CONFIG
# =============================================================================

app = Flask(__name__)

app.config.update(
    SECRET_KEY="super-secret-key-123",   # change in production
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    DATABASE=os.environ.get("FLASK_DB_PATH", "complaints.db"),
)

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# =============================================================================
# DATABASE
# =============================================================================

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(app.config["DATABASE"])
    cur = db.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            complaint TEXT NOT NULL,
            status TEXT DEFAULT 'OPEN',
            date TEXT,
            complaint_id TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            [
                ("admin@rvce", generate_password_hash("python@el"), "admin"),
                ("complaint_status", generate_password_hash("python@el"), "status_updater")
            ]
        )

    db.commit()
    db.close()

def get_stats():
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM complaints").fetchone()[0]
    open_c = db.execute("SELECT COUNT(*) FROM complaints WHERE status='OPEN'").fetchone()[0]
    return {
        "total": total,
        "open": open_c,
        "resolved": total - open_c
    }

# =============================================================================
# AUTH HELPERS
# =============================================================================

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("auth"):
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped

def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                return "Forbidden", 403
            return view(*args, **kwargs)
        return wrapped
    return decorator

# =============================================================================
# ROUTES
# =============================================================================

PHONE = re.compile(r"^[0-9+\-\s]{7,20}$")

@app.route("/")
def home():
    return render_template("home.html", s=get_stats())

@app.route("/add", methods=["GET", "POST"])
def add():
    error = msg = None

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        complaint = request.form.get("complaint", "").strip()

        if not name or not phone or not complaint:
            error = "All fields are required"
        elif not PHONE.match(phone):
            error = "Invalid phone number"
        else:
            db = get_db()
            cur = db.execute(
                "INSERT INTO complaints (name, phone, complaint, date) VALUES (?,?,?,date('now'))",
                (name, phone, complaint)
            )
            cid = f"CMP{cur.lastrowid:03d}"
            db.execute(
                "UPDATE complaints SET complaint_id=? WHERE id=?",
                (cid, cur.lastrowid)
            )
            db.commit()
            msg = f"Complaint submitted successfully (ID: {cid})"

    return render_template("add.html", error=error, msg=msg)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.update(
                auth=True,
                role=user["role"],
                username=user["username"],
                permanent=True
            )
            return redirect("/dashboard")

        error = "Invalid credentials"

    return render_template("login.html", error=error)

@app.route("/dashboard")
@login_required
def dashboard():
    rows = get_db().execute(
        "SELECT * FROM complaints ORDER BY id DESC"
    ).fetchall()
    return render_template("dashboard.html", rows=rows, s=get_stats())

@app.route("/resolve/<cid>", methods=["POST"])
@login_required
@role_required("admin", "status_updater")
def resolve(cid):
    db = get_db()
    db.execute(
        "UPDATE complaints SET status='RESOLVED' WHERE complaint_id=?",
        (cid,)
    )
    db.commit()
    return redirect("/dashboard")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect("/")

@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())

# =============================================================================

if __name__ == "__main__":
    init_db()
    print("🚀 ComplainNet running at http://127.0.0.1:5000")
    app.run(debug=True)
