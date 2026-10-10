# Secure-Login-System
For my Thiranex Project.



"""Secure Login System - Flask + SQLite + bcrypt (+ optional TOTP 2FA)

Install:  pip install flask bcrypt pyotp
Run:      python secure_login.py   ->  http://127.0.0.1:5000
"""
import os
import re
import sqlite3

import bcrypt
import pyotp
from flask import Flask, redirect, render_template_string, request, session

app = Flask(__name__)
app.secret_key = os.urandom(32)                  # signs the session cookie
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
DB = "users.db"

PAGE = """
<h2>{{ title }}</h2>
<p style="color:red">{{ msg }}</p>
<form method="post">
  {% for f in fields %}
    <input name="{{ f[0] }}" type="{{ f[1] }}" placeholder="{{ f[0] }}" required><br><br>
  {% endfor %}
  <button>{{ title }}</button>
</form>
<p><a href="/login">Login</a> | <a href="/register">Register</a></p>
"""


def db():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pw_hash BLOB NOT NULL,
        otp_secret TEXT NOT NULL)""")
    return con


def page(title, fields, msg=""):
    return render_template_string(PAGE, title=title, fields=fields, msg=msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    fields = [("username", "text"), ("password", "password")]
    if request.method == "GET":
        return page("Register", fields)

    user = request.form["username"].strip()
    pw = request.form["password"]

    # Input validation (whitelist)
    if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", user):
        return page("Register", fields, "Username: 3-20 letters/numbers/underscore.")
    if len(pw) < 8 or not re.search(r"\d", pw) or not re.search(r"[A-Za-z]", pw):
        return page("Register", fields, "Password: min 8 chars, letters and numbers.")

    hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())   # salted bcrypt hash
    secret = pyotp.random_base32()
    try:
        with db() as con:
            # "?" placeholders = parameterized query -> blocks SQL injection
            con.execute("INSERT INTO users(username, pw_hash, otp_secret) VALUES(?,?,?)",
                        (user, hashed, secret))
    except sqlite3.IntegrityError:
        return page("Register", fields, "Username already taken.")

    uri = pyotp.TOTP(secret).provisioning_uri(user, issuer_name="SecureLogin")
    return (f"<h3>Registered!</h3><p>Optional 2FA: add this secret to Google "
            f"Authenticator: <b>{secret}</b></p><p>URI: {uri}</p>"
            f"<a href='/login'>Go to login</a>")


@app.route("/login", methods=["GET", "POST"])
def login():
    fields = [("username", "text"), ("password", "password"),
              ("otp (leave blank if 2FA not set up)", "text")]
    if request.method == "GET":
        return page("Login", fields[:2] + [("otp", "text")])

    user = request.form["username"].strip()
    pw = request.form["password"].encode()
    otp = request.form.get("otp", "").strip()

    row = db().execute("SELECT id, pw_hash, otp_secret FROM users WHERE username=?",
                       (user,)).fetchone()
    # Same message for wrong user / wrong password (no user enumeration)
    if not row or not bcrypt.checkpw(pw, row[1]):
        return page("Login", fields[:2] + [("otp", "text")], "Invalid credentials.")

    # 2FA: only enforced if user typed a code (make it mandatory by removing the 'if')
    if otp and not pyotp.TOTP(row[2]).verify(otp):
        return page("Login", fields[:2] + [("otp", "text")], "Invalid 2FA code.")

    session.clear()
    session["user_id"], session["user"] = row[0], user
    return redirect("/dashboard")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:          # session check = protected page
        return redirect("/login")
    return f"<h2>Welcome, {session['user']}!</h2><a href='/logout'>Logout</a>"


@app.route("/logout")
def logout():
    session.clear()                       # destroy session
    return redirect("/login")


@app.route("/")
def home():
    return redirect("/dashboard")


if __name__ == "__main__":
    app.run(debug=False)
