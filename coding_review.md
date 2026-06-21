# Secure Coding Review & Source Code Audit Report

## 1. Vulnerable Code Analysis — `vulnerable_login.py`

The file `vulnerable_login.py` is an intentionally insecure Flask login application.  
It contains multiple common web application vulnerabilities, including SQL Injection, weak password hashing, hardcoded secrets, insecure cookies, reflected output risks, unrestricted file upload, and debug mode enabled.

### Full Vulnerable Source Code

```python
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

```

---

## 2. Main Security Findings in `vulnerable_login.py`

### Finding 1: Hardcoded Flask Secret Key

```python
app.secret_key = "admin123"
```

**Issue:**  
The Flask secret key is written directly inside the source code.

**Why this is dangerous:**  
If an attacker sees the source code, they can know the secret key and may be able to tamper with session data or application security mechanisms.

**Risk Level:** High

**Recommended Fix:**  
Store the secret key in an environment variable instead of hardcoding it.

---

### Finding 2: Hardcoded Database Credentials

```python
DB_USER     = "admin"
DB_PASSWORD = "root1234"
DB_NAME     = "users.db"
```

**Issue:**  
Database-related sensitive values are stored directly in the code.

**Why this is dangerous:**  
Hardcoded credentials can be leaked through GitHub, shared files, backups, screenshots, or logs.

**Risk Level:** Medium to High

**Recommended Fix:**  
Use environment variables or a secure configuration system.

---

### Finding 3: Weak Password Hashing Using MD5

```python
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```

**Issue:**  
The application uses MD5 to hash passwords.

**Why this is dangerous:**  
MD5 is considered broken and unsuitable for password storage. It is fast and easy to brute-force, especially because there is no salt.

**Risk Level:** High

**Recommended Fix:**  
Use a strong password hashing function such as PBKDF2, bcrypt, scrypt, or Argon2.

---

### Finding 4: SQL Injection in Login

```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
user  = conn.execute(query).fetchone()
```

**Issue:**  
User input is inserted directly into the SQL query using an f-string.

**Why this is dangerous:**  
An attacker may inject SQL code into the username field to bypass authentication or manipulate the database.

**Example Attack Idea:**

```text
' OR '1'='1
```

**Risk Level:** Critical

**Recommended Fix:**  
Use parameterized queries instead of string formatting.

---

### Finding 5: Insecure Cookie Usage

```python
resp.set_cookie("user", username)
```

**Issue:**  
The username is stored directly inside a cookie without important security flags.

**Why this is dangerous:**  
Cookies without `HttpOnly`, `Secure`, and proper session handling can be stolen or manipulated.

**Risk Level:** High

**Recommended Fix:**  
Use Flask sessions and configure cookies securely.

---

### Finding 6: Reflected Output / Possible XSS

```python
resp = make_response("Welcome " + username)
```

**Issue:**  
User input is directly included in the response.

**Why this is dangerous:**  
If the username contains malicious HTML or JavaScript, it may be reflected back to the browser.

**Risk Level:** Medium to High

**Recommended Fix:**  
Use template escaping and avoid directly concatenating user input into HTML responses.

---

### Finding 7: Verbose Error Message

```python
error = f"No user '{username}' found in {DB_NAME}"
```

**Issue:**  
The application reveals internal information such as database name and submitted username.

**Why this is dangerous:**  
Attackers can use detailed error messages to understand the backend structure.

**Risk Level:** Medium

**Recommended Fix:**  
Use generic messages such as:

```text
Invalid username or password.
```

---

### Finding 8: No Input Validation During Registration

```python
username = request.form["username"]
password = request.form["password"]
```

**Issue:**  
The application accepts any username and password without checking length, format, or password strength.

**Why this is dangerous:**  
Weak passwords and unexpected input can lead to security and stability problems.

**Risk Level:** Medium

**Recommended Fix:**  
Validate username length and enforce password complexity rules.

---

### Finding 9: SQL Injection in Registration

```python
conn.execute(f"INSERT INTO users VALUES (NULL,'{username}','{hashed}')")
```

**Issue:**  
The registration function also inserts user input directly into an SQL query.

**Why this is dangerous:**  
Attackers may inject SQL code while creating an account.

**Risk Level:** Critical

**Recommended Fix:**  
Use parameterized SQL insert statements.

---

### Finding 10: Unrestricted File Upload

```python
f.save("uploads/" + f.filename)
```

**Issue:**  
The uploaded filename is trusted directly.

**Why this is dangerous:**  
This can allow path traversal attacks or uploading dangerous file types.

**Example Risk:**

```text
../../malicious.py
```

**Risk Level:** High

**Recommended Fix:**  
Use `secure_filename()`, validate file extensions, limit file size, and require authentication.

---

### Finding 11: Debug Mode Enabled

```python
app.run(debug=True)
```

**Issue:**  
Debug mode is enabled.

**Why this is dangerous:**  
Debug mode can expose sensitive error pages and interactive debugger features.

**Risk Level:** High

**Recommended Fix:**  
Disable debug mode in production.

---

## 3. Secure Code Analysis — `secure_login.py`

The file `secure_login.py` is the secure refactored version of the vulnerable application.  
It fixes the main vulnerabilities by using environment variables, strong password hashing, parameterized queries, Flask sessions, input validation, secure file upload handling, and safer debug configuration.

### Full Secure Source Code

```python
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

```

---

## 4. Security Improvements in `secure_login.py`

### Improvement 1: Secret Key Loaded Securely

```python
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
```

**What changed:**  
The secret key is no longer hardcoded.

**Why this is better:**  
Sensitive secrets are separated from the source code and can be managed safely through environment variables.

---

### Improvement 2: Strong Password Hashing

```python
return generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
```

**What changed:**  
The secure version uses PBKDF2-SHA256 with salt.

**Why this is better:**  
This makes password cracking much harder compared to MD5.

---

### Improvement 3: Password Verification Function

```python
return check_password_hash(stored, provided)
```

**What changed:**  
Passwords are verified using a secure built-in function.

**Why this is better:**  
The application does not compare plain text passwords or weak hashes manually.

---

### Improvement 4: Parameterized Query in Login

```python
user = conn.execute(
    "SELECT id, username, password FROM users WHERE username = ?",
    (username,)
).fetchone()
```

**What changed:**  
The SQL query uses placeholders instead of direct string formatting.

**Why this is better:**  
Parameterized queries prevent SQL Injection because user input is treated as data, not executable SQL code.

---

### Improvement 5: Proper Session Management

```python
session.clear()
session["user_id"]  = user[0]
session["username"] = user[1]
```

**What changed:**  
The secure version uses Flask sessions instead of manually setting insecure cookies.

**Why this is better:**  
Session management is safer and easier to control.

---

### Improvement 6: Generic Error Messages

```python
error = "Invalid username or password."
```

**What changed:**  
The application no longer reveals whether a username exists or what database is being used.

**Why this is better:**  
Generic errors reduce information leakage.

---

### Improvement 7: Input Validation

```python
if not username or not password or len(username) > 80:
    error = "Invalid input."
```

**What changed:**  
The secure version checks empty fields and username length.

**Why this is better:**  
Input validation helps prevent unexpected data and reduces attack surface.

---

### Improvement 8: Password Policy

```python
elif len(password) < 8:
    error = "Password must be at least 8 characters."
elif not any(c.isupper() for c in password):
    error = "Password must contain an uppercase letter."
elif not any(c.isdigit() for c in password):
    error = "Password must contain a digit."
```

**What changed:**  
The registration route now enforces stronger passwords.

**Why this is better:**  
Weak passwords are easier to guess or brute-force.

---

### Improvement 9: Secure SQL Insert

```python
conn.execute(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    (username, hashed)
)
```

**What changed:**  
Registration now uses a parameterized insert query.

**Why this is better:**  
This prevents SQL Injection during account creation.

---

### Improvement 10: Authentication Required for Upload

```python
if "user_id" not in session:
    return redirect(url_for("login"))
```

**What changed:**  
Only authenticated users can upload files.

**Why this is better:**  
Unauthenticated users cannot abuse the upload endpoint.

---

### Improvement 11: File Type Validation

```python
ALLOWED_EXT  = {"png", "jpg", "jpeg", "gif", "pdf"}
```

**What changed:**  
Only specific file extensions are allowed.

**Why this is better:**  
This reduces the risk of uploading executable or dangerous files.

---

### Improvement 12: File Size Limit

```python
MAX_SIZE = 2 * 1024 * 1024
```

**What changed:**  
Uploaded files are limited to 2 MB.

**Why this is better:**  
This helps prevent storage abuse and denial-of-service style attacks.

---

### Improvement 13: Secure Filename Handling

```python
filename = secure_filename(f.filename)
```

**What changed:**  
The filename is sanitized before saving.

**Why this is better:**  
This prevents path traversal and unsafe filenames.

---

### Improvement 14: Debug Mode Controlled by Environment Variable

```python
debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
app.run(debug=debug)
```

**What changed:**  
Debug mode is not always enabled.

**Why this is better:**  
Production environments can run safely without exposing debug features.

---

