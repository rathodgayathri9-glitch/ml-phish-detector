# app/app.py
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from passlib.hash import sha256_crypt
import sqlite3
import joblib
import os
import sys
from datetime import datetime

# ensure src is importable
BASE_DIR = os.path.dirname(os.path.abspath(__file__))           # .../phish-detect/app
SRC_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "src"))   # .../phish-detect/src
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

try:
    import feature_extractor as fe
except Exception:
    fe = None

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "super-secret-key-change-this"  # change for production

DB_PATH = "/tmp/database.db"
MODEL_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "models", "phishing_model.pkl"))

# load model if present (optional)
model = None
try:
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
except Exception as e:
    app.logger.warning("Model load failed: %s", e)
    model = None

# DB helper
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

# flask-login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT id, username, email FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    con.close()
    if row:
        return User(row["id"], row["username"], row["email"])
    return None

# -----------------------
# Routes
# -----------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not email or not password:
            flash("Please fill all fields.", "warning")
            return redirect(url_for("signup"))
        hashed = sha256_crypt.hash(password)
        con = get_db()
        cur = con.cursor()
        try:
            cur.execute("INSERT INTO users(username, email, password) VALUES (?, ?, ?)",
                        (username, email, hashed))
            con.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already registered. Try login.", "danger")
            return redirect(url_for("signup"))
        finally:
            con.close()
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        con = get_db()
        cur = con.cursor()
        cur.execute("SELECT id, username, password FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        con.close()
        if row and sha256_crypt.verify(password, row["password"]):
            user = User(row["id"], row["username"], email)
            login_user(user)
            flash("Logged in.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT id, url, result, scanned_at FROM scans WHERE user_id=? ORDER BY id DESC", (current_user.id,))
    rows = cur.fetchall()
    con.close()
    return render_template("dashboard.html", scans=rows)

# standalone scan page (GET shows form; POST runs scan)
@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            flash("Please enter a URL.", "warning")
            return redirect(url_for("scan"))

        # extract features if fe available
        feature_vector = None
        try:
            if fe:
                feats = fe.extract_features(url)
                feature_vector = [list(feats.values())]
        except Exception as e:
            app.logger.warning("Feature extraction failed: %s", e)
            feature_vector = None

        # model prediction -> expect "phishing" or "legit"
        verdict = None
        prob = None
        try:
            if model and feature_vector:
                raw = model.predict(feature_vector)
                verdict = raw[0] if hasattr(raw, "__len__") else raw
                if hasattr(model, "predict_proba"):
                    prob = float(model.predict_proba(feature_vector)[0].max())
            else:
                # fallback heuristic
                verdict = "phishing" if ("login" in url.lower() or "verify" in url.lower() or url.count("/") > 3) else "legit"
        except Exception as e:
            app.logger.warning("Model prediction error: %s", e)
            verdict = "phishing" if ("login" in url.lower() or "verify" in url.lower()) else "legit"

        # save scan
        con = get_db()
        cur = con.cursor()
        cur.execute("INSERT INTO scans (user_id, url, result, scanned_at) VALUES (?, ?, ?, ?)",
                    (current_user.id, url, verdict, datetime.utcnow().isoformat()))
        con.commit()
        con.close()

        # redirect to result page (GET) — pass verdict & url as query args
        return redirect(url_for("result", verdict=verdict, url=url))
    # GET
    return render_template("scan.html")

@app.route("/result")
@login_required
def result():
    verdict = request.args.get("verdict")
    link = request.args.get("link")
    prob = request.args.get("prob", None)

    return render_template("result.html", 
                           url=link, 
                           result=verdict, 
                           prob=prob)


# admin (simple)
@app.route("/admin")
@login_required
def admin():
    # naive admin: user_id == 1
    if current_user.id != 1:
        abort(403)
    con = get_db()
    cur = con.cursor()
    cur.execute("SELECT id, username, email FROM users ORDER BY id ASC")
    users = cur.fetchall()
    cur.execute("SELECT id, user_id, url, result, scanned_at FROM scans ORDER BY scanned_at DESC LIMIT 500")
    scans = cur.fetchall()
    con.close()
    return render_template("admin.html", users=users, scans=scans)

# errors
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html", error=str(e)), 500

# toggle theme (optional)
@app.post("/toggle-theme")
def toggle_theme():
    current = session.get("theme", "light")
    session["theme"] = "dark" if current == "light" else "light"
    return ("", 204)

# health
@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    app.run()

