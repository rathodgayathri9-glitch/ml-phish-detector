# app/app.py
import os, sys, sqlite3, joblib
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash,
    jsonify, send_from_directory, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user, current_user
)
from passlib.hash import sha256_crypt

# --- Allow importing src/feature_extractor ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))         # .../phish-detect/app
SRC_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "src")) # .../phish-detect/src
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
try:
    import feature_extractor as fe
except Exception:
    fe = None

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("PHISHDETECT_SECRET", "change_this_secret_for_prod")

DB_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "database.db"))
MODEL_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "models", "phishing_model.pkl"))

# load model safely
model = None
try:
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        app.logger.info("Loaded model from %s", MODEL_PATH)
    else:
        app.logger.info("No model found at %s — running heuristic fallback", MODEL_PATH)
except Exception as e:
    app.logger.warning("Model load failed: %s", e)
    model = None

def get_db():
    conn = sqlite3.connect(DB_PATH)
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
        return User(row[0], row[1], row[2])
    return None

# ---------------- Routes ----------------

@app.route("/")
def index():
    return render_template("index.html")

# Static demo page route (optional) — serves the demo in static folder
@app.route("/ae3-demo")
def ae3_demo():
    # file is app/static/ae3_demo.html
    return send_from_directory(app.static_folder, "ae3_demo.html")

# Signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not username or not email or not password:
            flash("Please fill all fields.", "warning"); return redirect(url_for("signup"))
        hashed = sha256_crypt.hash(password)
        try:
            con = get_db(); cur = con.cursor()
            cur.execute("INSERT INTO users(username, email, password) VALUES (?, ?, ?)",
                        (username, email, hashed))
            con.commit(); con.close()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already registered.", "danger"); return redirect(url_for("signup"))
        except Exception as e:
            flash(f"Error creating account: {e}", "danger"); return redirect(url_for("signup"))
    return render_template("signup.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        con = get_db(); cur = con.cursor()
        cur.execute("SELECT id, username, password FROM users WHERE email=?", (email,))
        row = cur.fetchone(); con.close()
        if row and sha256_crypt.verify(password, row[2]):
            user = User(row[0], row[1], email)
            login_user(user)
            flash("Logged in.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")

# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# Dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    con = get_db(); cur = con.cursor()
    cur.execute("SELECT id, url, result, scanned_at FROM scans WHERE user_id=? ORDER BY id DESC", (current_user.id,))
    rows = cur.fetchall(); con.close()
    return render_template("dashboard.html", scans=rows)

# Result viewer (GET) used when redirecting after a scan
@app.route("/result")
@login_required
def result():
    verdict = request.args.get("verdict")
    link = request.args.get("link")
    prob = request.args.get("prob")
    # prob may be None; templates should handle missing prob
    return render_template("result.html", url=link, result=verdict, prob=prob)

# Scan page (form posts here) — uses /api/analyze internally
@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            flash("Please enter a URL.", "warning"); return redirect(url_for("scan"))
        # call internal analyze logic (same as /api/analyze)
        resp = analyze_url_internal(url, current_user.id)
        # resp is dict with keys: verdict, prob, features, explain
        # store verdict and redirect to result view
        return redirect(url_for("result", verdict=resp["verdict"], link=url, prob=resp.get("prob")))
    return render_template("scan.html")

# Admin (very basic)
@app.route("/admin")
@login_required
def admin():
    if current_user.id != 1:
        abort(403)
    con = get_db(); cur = con.cursor()
    cur.execute("SELECT id, username, email FROM users ORDER BY id ASC"); users = cur.fetchall()
    cur.execute("SELECT id, user_id, url, result, scanned_at FROM scans ORDER BY scanned_at DESC LIMIT 500"); scans = cur.fetchall()
    con.close()
    return render_template("admin.html", users=users, scans=scans)

# ---------- Prediction logic (internal) ----------
def interpret_raw_prediction(raw):
    """
    Convert raw model output to normalized verdict string and numeric label.
    Returns (verdict_string, numeric_label)
    """
    # If numeric 0/1
    try:
        if isinstance(raw, (list, tuple)) or hasattr(raw, "__len__"):
            raw = raw[0]
    except Exception:
        pass

    if isinstance(raw, (int, float)):
        # assume 1 => phishing, 0 => legit (matches training script)
        num = int(raw)
        return ("phishing" if num == 1 else "legit", num)
    if isinstance(raw, str):
        s = raw.lower()
        if "phish" in s: return ("phishing", 1)
        if "legit" in s or "safe" in s: return ("legit", 0)
        # fallback
        return (s, 1 if "1" in s else 0)
    # fallback unknown
    return ("phishing", 1)

def analyze_url_internal(url, user_id=None):
    """
    Core analyze function used by both the API and the /scan route.
    Returns dict {verdict, prob, features, explanation, attention}
    """
    # Extract features using your src/feature_extractor.extract_features (must return dict)
    features = None
    feature_vector = None
    if fe:
        try:
            features = fe.extract_features(url)
            # preserve the same order of features as used for training
            feature_order = ["url_length", "dot_count", "hyphen_count", "has_ip",
                             "https_used", "suspicious_keywords", "domain_length"]
            feature_vector = [[features.get(k, 0) for k in feature_order]]
        except Exception as e:
            app.logger.warning("Feature extraction failed: %s", e)
            features = None
            feature_vector = None

    # Model prediction
    prob = None
    raw_pred = None
    if model and feature_vector:
        try:
            raw_pred = model.predict(feature_vector)
            verdict, numeric = interpret_raw_prediction(raw_pred)
            # compute probability for 'phishing' if possible
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba(feature_vector)[0]
                # find index for phishing class in model.classes_ if string labels
                if hasattr(model, "classes_"):
                    classes = list(model.classes_)
                    # if classes contain 'phishing' or 1
                    if "phishing" in classes:
                        idx = classes.index("phishing")
                        prob = float(proba[idx])
                    else:
                        # find index correspond to numeric 1 if classes numeric
                        try:
                            idx = classes.index(1)
                            prob = float(proba[idx])
                        except ValueError:
                            prob = max(map(float, proba))  # fallback
                else:
                    prob = max(map(float, proba))
        except Exception as e:
            app.logger.warning("Model predict failed: %s", e)
            raw_pred = None
    # fallback heuristic if model missing or feature extraction failed
    if raw_pred is None:
        heur = 0
        u = url.lower()
        heur += ("login" in u or "verify" in u) * 0.6
        heur += ("@" in u) * 0.4
        heur += ("http:" in u and "https:" not in u) * 0.35
        heur += (u.count("/") > 3) * 0.2
        score = min(0.99, heur)
        verdict = "phishing" if score > 0.5 else "legit"
        prob = score

    # store into DB
    try:
        con = get_db(); cur = con.cursor()
        cur.execute(
            "INSERT INTO scans(user_id, url, result, scanned_at) VALUES (?, ?, ?, ?)",
            (user_id, url, verdict, datetime.utcnow().isoformat())
        )
        con.commit(); con.close()
    except Exception as e:
        app.logger.warning("Could not save scan to DB: %s", e)

    explanation = []
    attention = {}
    # If fe provided, optionally craft a short explanation
    if features:
        if features.get("suspicious_keywords", 0) > 0:
            explanation.append("Suspicious keywords in URL")
        if features.get("has_ip", 0):
            explanation.append("URL uses raw IP address")
        if not features.get("https_used", 1):
            explanation.append("Missing HTTPS")
        if features.get("url_length", 0) > 80:
            explanation.append("Very long URL")
        # minimal attention sim
        attention = {"domain":0.3, "page":0.25, "script":0.2, "form":0.15, "external_link":0.1}

    return {"verdict": verdict, "prob": prob, "features": features or {}, "explanation": explanation, "attention": attention}

# REST API that accepts JSON and returns JSON result
@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url") or request.form.get("url")
    if not url:
        return jsonify({"error":"missing url"}), 400
    user_id = current_user.id if current_user.is_authenticated else None
    res = analyze_url_internal(url, user_id=user_id)
    return jsonify(res)

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("500.html", error=str(e)), 500

if __name__ == "__main__":
    app.run(debug=True)
