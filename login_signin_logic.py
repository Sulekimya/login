from flask import Flask, request, render_template, redirect, session
import hashlib, hmac, os
import sqlite3

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            dob DATE,
            gender TEXT,
            address TEXT
        )
    ''')
    conn.commit()
    conn.close()


# Helper function to hash password with salt
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    ).hex()


# Verify login
def verify_user(name, password):
    conn = get_db()
    cur = conn.execute("SELECT * FROM users WHERE name = ?", (name,))
    user = cur.fetchone()
    conn.close()
    if not user:
        return False
    salt = bytes.fromhex(user["salt"])
    new_hash = hash_password(password, salt)
    return hmac.compare_digest(new_hash, user["password_hash"])


# Routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def register():
    name = request.form.get("name", "").strip()
    password = request.form.get("password", "")
    dob = request.form.get("dob", "")
    gender = request.form.get("gender", "")
    address = request.form.get("address", "")

    # Basic validation
    if not name or not password or not dob or not gender or not address:
        return "All fields are required."

    conn = get_db()
    cur = conn.execute("SELECT id FROM users WHERE name = ?", (name,))
    if cur.fetchone():
        conn.close()
        return "User already exists."

    salt = os.urandom(16)
    password_hash = hash_password(password, salt)

    conn.execute(
        "INSERT INTO users (name, password_hash, salt, dob, gender, address) VALUES (?, ?, ?, ?, ?, ?)",
        (name, password_hash, salt.hex(), dob, gender, address)
    )
    conn.commit()
    conn.close()
    return "successfully registered."


@app.route("/login", methods=["POST"])
def login():
    name = request.form.get("name", "").strip()
    password = request.form.get("password", "")

    if verify_user(name, password):
        session["user"] = name
        return f"Welcome {name}!"
    else:
        return "Invalid login details."


@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return render_template("dashboard.html")
    else:
        return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
