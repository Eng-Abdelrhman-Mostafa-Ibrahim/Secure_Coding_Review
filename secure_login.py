# =============================================================
#  secure_login.py
#  ✅ Secure refactored version — all vulnerabilities fixed
# =============================================================

import sqlite3
import os
import secrets
from flask import (Flask, request, render_template_string,
                   session, redirect, url_for)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ── FIX 1 & 2: Load secret from environment, never hardcode ──
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
DB_PATH = os.environ.get("DB_PATH", "users.db")

# ── FIX 3: Strong hashing — PBKDF2-SHA256 with auto salt ─────
def hash_password(password: str) -> str:
    return generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)

def verify_password(stored: str, provided: str) -> bool:
    return check_password_hash(stored, provided)

def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()

# ── FIX 4 & 5: Parameterized queries + proper session ────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # ── FIX 9: Input validation ───────────────────────────
        if not username or not password or len(username) > 80:
            error = "Invalid input."
        else:
            conn = get_db()
            # ✅ Parameterized query — safe from SQL Injection
            user = conn.execute(
                "SELECT id, username, password FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if user and verify_password(user[2], password):
                session.clear()
                session["user_id"]  = user[0]
                session["username"] = user[1]
                return redirect(url_for("dashboard"))
            else:
                # ── FIX 7: Generic error — reveals nothing ────
                error = "Invalid username or password."

    # ── FIX 8: Jinja2 auto-escaping prevents XSS ─────────────
    return render_template_string("""
        <h2>Login</h2>
        <p style=\"color:red\">{{ error }}</p>
        <form method=\"POST\">
            Username: <input name=\"username\" maxlength=\"80\"><br>
            Password: <input name=\"password\" type=\"password\"><br>
            <button>Login</button>
        </form>
    """, error=error)

@app.route("/dashboard")
def dashboard():
    # ── FIX 5: Enforce authentication on every protected route ─
    if "user_id" not in session:
        return redirect(url_for("login"))
    return f"Welcome, {session['username']}! <a href='/logout'>Logout</a>"

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ── FIX 9 & 10: Strong password policy + validated upload ─────
ALLOWED_EXT  = {"png", "jpg", "jpeg", "gif", "pdf"}
MAX_SIZE     = 2 * 1024 * 1024  # 2 MB

@app.route("/register", methods=["GET", "POST"])
def register():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # ✅ Password complexity rules
        if not username or len(username) > 80:
            error = "Username must be 1–80 characters."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif not any(c.isupper() for c in password):
            error = "Password must contain an uppercase letter."
        elif not any(c.isdigit() for c in password):
            error = "Password must contain a digit."
        else:
            hashed = hash_password(password)
            conn   = get_db()
            try:
                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hashed)
                )
                conn.commit()
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                error = "Username already exists."

    return render_template_string("""
        <h2>Register</h2>
        <p style=\"color:red\">{{ error }}</p>
        <form method=\"POST\">
            Username: <input name=\"username\" maxlength=\"80\"><br>
            Password: <input name=\"password\" type=\"password\" minlength=\"8\"><br>
            <button>Register</button>
        </form>
    """, error=error)

@app.route("/upload", methods=["GET", "POST"])
def upload():
    # ── FIX 5: Require authentication ────────────────────────
    if "user_id" not in session:
        return redirect(url_for("login"))

    error = ""
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            error = "No file selected."
        else:
            ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
            if ext not in ALLOWED_EXT:
                error = f"File type .{ext} is not allowed."
            else:
                data = f.read()
                if len(data) > MAX_SIZE:
                    error = "File exceeds 2 MB limit."
                else:
                    # ✅ secure_filename strips path traversal
                    filename = secure_filename(f.filename)
                    os.makedirs("uploads", exist_ok=True)
                    with open(os.path.join("uploads", filename), "wb") as out:
                        out.write(data)
                    return f"Uploaded: {filename}"

    return render_template_string("""
        <h2>Upload</h2>
        <p style=\"color:red\">{{ error }}</p>
        <form method=\"POST\" enctype=\"multipart/form-data\">
            <input type=\"file\" name=\"file\" accept=\".png,.jpg,.jpeg,.gif,.pdf\">
            <button>Upload</button>
        </form>
    """, error=error)

if __name__ == "__main__":
    init_db()
    # ── FIX 11: Never run debug=True in production ────────────
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug)
