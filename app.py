from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import time
from flask import flash

app = Flask(__name__)
app.secret_key = "secret123"

# Create DB
def init_db():
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    attempts INTEGER DEFAULT 0,
    lock_time REAL DEFAULT 0
)''')
    conn.commit()
    conn.close()

init_db()

# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # 🔐 Input Validation
        if not username or not password:
            return "Fields cannot be empty"

        if len(password) < 6:
            return "Password must be at least 6 characters"

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        conn = sqlite3.connect("users.db")
        cur = conn.cursor()

        try:
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
            conn.commit()
        except:
            conn.close()
            return "Username already exists!"

        conn.close()
        return redirect("/login")

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cur.fetchone()

        if user:
            attempts = user[3]
            lock_time = user[4]

            # ⏱️ Check if still locked
            if time.time() < lock_time:
                flash("Account is temporarily locked. Try again later.", "error")
                conn.close()
                return redirect("/login")

            # 🔐 Check password
            if bcrypt.checkpw(password.encode(), user[2]):
                cur.execute("UPDATE users SET attempts=0 WHERE username=?", (username,))
                conn.commit()
                session["user"] = username
                conn.close()
                return redirect("/dashboard")
            else:
                attempts += 1

                # ❗ Lock after 3 attempts
                if attempts >= 3:
                    lock_until = time.time() + 60
                    cur.execute("UPDATE users SET attempts=?, lock_time=? WHERE username=?", 
                                (attempts, lock_until, username))
                    conn.commit()
                    conn.close()
                    flash("Account locked for 1 minute!", "error")
                    return redirect("/login")
                else:
                    cur.execute("UPDATE users SET attempts=? WHERE username=?", (attempts, username))
                    conn.commit()
                    conn.close()
                    flash(f"Wrong password! Attempts left: {3 - attempts}", "error")
                    return redirect("/login")

        conn.close()
        flash("Invalid credentials", "error")
        return redirect("/login")

    return render_template("login.html")



@app.route("/")
def home():
    return redirect("/login")


# Dashboard
@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return render_template("dashboard.html", user=session["user"])
    return redirect("/login")


# Logout
@app.route("/logout")  #When user opens /login → run this function
def logout():
    session.pop("user", None)
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)