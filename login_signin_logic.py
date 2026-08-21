from flask import Flask, request, render_template, redirect, session
import os
from supabase import create_client, Client

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# ---------- Supabase setup ----------
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_ANON_KEY = os.environ["SUPABASE_ANON_KEY"]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


# Routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def register():
    email = request.form.get("name", "").strip()  # using the same "name" field as email
    password = request.form.get("password", "")
    dob = request.form.get("dob", "")
    gender = request.form.get("gender", "")
    address = request.form.get("address", "")

    # Basic validation
    if not email or not password or not dob or not gender or not address:
        return "All fields are required."

    try:
        result = supabase.auth.sign_up({"email": email, "password": password})
    except Exception as e:
        return f"Registration failed: {e}"

    user = result.user
    if not user:
        return "User already exists or registration failed."

    # Extra profile fields go in the separate "profiles" table
    try:
        supabase.table("profiles").insert({
            "id": user.id,
            "dob": dob,
            "gender": gender,
            "address": address,
        }).execute()
    except Exception as e:
        return f"Account created but profile save failed: {e}"

    return "successfully registered."


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("name", "").strip()
    password = request.form.get("password", "")

    try:
        result = supabase.auth.sign_in_with_password({"email": email, "password": password})
    except Exception:
        return "Invalid login details."

    session.clear()
    session["access_token"] = result.session.access_token
    session["refresh_token"] = result.session.refresh_token
    session["user"] = result.user.email
    session["user_id"] = result.user.id

    return f"Welcome {email}!"


@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return render_template("dashboard.html")
    else:
        return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)
