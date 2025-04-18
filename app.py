from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
import os
import hashlib

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Used for session management

# Database setup
def create_tables():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    
    cursor.execute("CREATE TABLE IF NOT EXISTS admin_users (username TEXT, password TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS detected_attacks (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT, reason TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    cursor.execute("CREATE TABLE IF NOT EXISTS blocked_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")

    # Add default admin user if not exists
    cursor.execute("SELECT * FROM admin_users WHERE username = 'admin'")
    if cursor.fetchone() is None:
        password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute("INSERT INTO admin_users VALUES (?, ?)", ("admin", password_hash))

    conn.commit()
    conn.close()

def get_detected_attacks():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, reason, timestamp FROM detected_attacks ORDER BY timestamp DESC LIMIT 10")
    attacks = cursor.fetchall()
    conn.close()
    return attacks

def get_blocked_ips():
    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address FROM blocked_ips")
    blocked = cursor.fetchall()
    conn.close()
    return [ip[0] for ip in blocked]

@app.route("/")
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    attacks = get_detected_attacks()
    blocked_ips = get_blocked_ips()
    return render_template("index.html", attacks=attacks, blocked_ips=blocked_ips)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = sqlite3.connect("firewall.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin_users WHERE username = ? AND password = ?", (username, password_hash))
        user = cursor.fetchone()
        conn.close()

        if user:
            session["user"] = username
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials. Try again.", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

@app.route("/unblock", methods=["POST"])
def unblock():
    if "user" not in session:
        return redirect(url_for("login"))

    ip = request.form["ip"]
    os.system(f"sudo iptables -D INPUT -s {ip} -j DROP")

    conn = sqlite3.connect("firewall.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))
    conn.commit()
    conn.close()

    flash(f"Unblocked IP: {ip}", "success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    create_tables()
    app.run(host="0.0.0.0", port=5000, debug=True)
