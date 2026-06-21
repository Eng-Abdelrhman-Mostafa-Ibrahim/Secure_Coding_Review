# =============================================================
#  vulnerable_login.py
#  ⚠️  INTENTIONALLY INSECURE — For educational review only
#  DO NOT deploy this code anywhere
# =============================================================

import sqlite3
import hashlib
from flask import Flask, request, render_template_string, make_response

app = Flask(__name__)

# ── VULN 1: Hardcoded secret key ─────────────────────────────
app.secret_key = "admin123"

# ── VULN 2: Hardcoded DB credentials ─────────────────────────
DB_USER     = "admin"
DB_PASSWORD = "root1234"
DB_NAME     = "users.db"

# ── VULN 3: Weak hashing — MD5 (broken, no salt) ─────────────
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def get_db():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    """)
    conn.commit()

# ── VULN 4: SQL Injection (string interpolation in query) ─────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed   = hash_password(password)
        conn     = get_db()

        # ❌ Directly inserting user input into SQL string
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
        user  = conn.execute(query).fetchone()

        if user:
            # ── VULN 5: No session token — insecure cookie ────
            resp = make_response("Welcome " + username)  # VULN 6: XSS
            resp.set_cookie("user", username)            # plain text, no httponly
            return resp
        else:
            # ── VULN 7: Verbose error leaks internals ─────────
            error = f"No user '{username}' found in {DB_NAME}"

    # ── VULN 8: User input reflected into HTML (XSS) ─────────
    return render_template_string("""
        <h2>Login</h2>
        <p style=\"color:red\">{{ error }}</p>
        <form method=\"POST\">
            Username: <input name=\"username\"><br>
            Password: <input name=\"password\" type=\"password\"><br>
            <button>Login</button>
        </form>
    """, error=error)

# ── VULN 9: No input validation on registration ───────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]  # no length/format check
        password = request.form["password"]  # 1 character accepted
        hashed   = hash_password(password)
        conn     = get_db()
        # ❌ SQL Injection again
        conn.execute(f"INSERT INTO users VALUES (NULL,'{username}','{hashed}')")
        conn.commit()
        return "Registered!"
    return render_template_string("""
        <h2>Register</h2>
        <form method=\"POST\">
            Username: <input name=\"username\"><br>
            Password: <input name=\"password\" type=\"password\"><br>
            <button>Register</button>
        </form>
    """)

# ── VULN 10: Unrestricted file upload ─────────────────────────
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        f = request.files["file"]
        f.save("uploads/" + f.filename)   # path traversal + any file type
        return "Uploaded: " + f.filename  # XSS in filename
    return render_template_string("""
        <h2>Upload</h2>
        <form method=\"POST\" enctype=\"multipart/form-data\">
            <input type=\"file\" name=\"file\">
            <button>Upload</button>
        </form>
    """)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)  # ── VULN 11: debug=True exposes debugger
