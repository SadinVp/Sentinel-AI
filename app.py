
from flask import Flask, request, abort, render_template
from flask_login import LoginManager
from urllib.parse import unquote
import joblib

from extensions import db
from routes.auth import auth_bp
from routes.main import main_bp
from routes.xssdemo import xss_bp
from models.user import User
import os
import csv
from datetime import datetime

# Ensure the data folder exists at startup
os.makedirs("data", exist_ok=True)


def log_quarantine(request_text, score, layer):
    import os
    import csv
    from datetime import datetime

    # Ensure the data folder exists
    os.makedirs("data", exist_ok=True)

    # Path to the quarantine CSV file
    file_path = "data/global_quarantine.csv"

    # Check if file exists to write header
    file_exists = os.path.exists(file_path)

    # Open file in append mode
    with open(file_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Write header if file is new
        if not file_exists:
            writer.writerow(["timestamp", "layer", "request", "score"])

        # Write the log entry
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            layer,
            request_text,
            round(score, 4)
        ])



# ===============================
# App Config
# ===============================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Dinu2004@localhost/sentinel_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Ensure the data folder exists at startup
os.makedirs("data", exist_ok=True)


# ===============================
# Safe Paths (skip WAF)
# ===============================
SAFE_PATHS = ["/static", "/favicon.ico", "/test-log"]



# ===============================
# Request Extraction (GLOBAL)
# ==============================
def extract_request_data(req):
    parts = []

    # Method + full path (path + query)
    parts.append(req.method)
    parts.append(req.full_path)

    # Query string
    if req.query_string:
        parts.append(unquote(req.query_string.decode("utf-8", errors="ignore")))

    # Body (POST/PUT)
    if req.data:
        parts.append(unquote(req.data.decode("utf-8", errors="ignore")))

    # Headers (very important)
    for key, value in req.headers.items():
        parts.append(f"{key}:{unquote(value)}")

    # Cookies
    for key, value in req.cookies.items():
        parts.append(f"{key}={unquote(value)}")

    return " ".join(parts).lower()



# ===============================
# Load GLOBAL WAF model
# ===============================

global_model = joblib.load("global_model.joblib1")
global_vectorizer = joblib.load("global_vectorizer.joblib1")

QUARANTINE_THRESHOLD = 0.40   # for retraining dataset
BLOCK_THRESHOLD = 0.65        # for security enforcement


# ===============================
# Load SQLi model
# ===============================
sqli_model = joblib.load("models/sqli_model.joblib")
sqli_vectorizer = joblib.load("models/sqli_vectorizer.joblib")

SQLI_QUARANTINE_THRESHOLD = 0.35
SQLI_BLOCK_THRESHOLD = 0.70

def log_sqli_quarantine(payload, score):
    os.makedirs("data", exist_ok=True)
    file_path = "data/sqli_quarantine.csv"
    file_exists = os.path.exists(file_path)

    with open(file_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(["timestamp", "context", "payload", "score"])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "REQUEST_PARAM",
            payload,
            round(score, 4)
        ])



# ===============================
# GLOBAL WAF (Layer 1)
# ===============================
@app.before_request
def global_waf():
    if any(request.path.startswith(p) for p in SAFE_PATHS):
        return

    full_request = extract_request_data(request)
    vec = global_vectorizer.transform([full_request])
    probability = global_model.predict_proba(vec)[0][1]

    # Debug (always visible)
    print("GLOBAL WAF SCORE:", probability)

    # 1️⃣ Quarantine for retraining (learning decision)
    if probability >= QUARANTINE_THRESHOLD:
        log_quarantine(full_request, probability, "GLOBAL")

    # 2️⃣ Block if clearly malicious (security decision)
    if probability >= BLOCK_THRESHOLD:
        abort(403, description="Blocked by Global WAF")
   




# ===============================
# SQLi WAF (Layer 2)
# ===============================
@app.before_request
def sqli_waf():
    if any(request.path.startswith(p) for p in SAFE_PATHS):
        return

    for _, value in {**request.args, **request.form}.items():
        decoded_value = unquote(value).lower().strip()

        if not decoded_value:
            continue

        vec = sqli_vectorizer.transform([decoded_value])

        # 🔹 Probability instead of hard label
        probability = sqli_model.predict_proba(vec)[0][1]

        print("SQLI SCORE:", probability, "| PAYLOAD:", decoded_value)

        # 1️⃣ Quarantine (learning decision)
        if probability >= SQLI_QUARANTINE_THRESHOLD:
            log_sqli_quarantine(decoded_value, probability)

        # 2️⃣ Block (security decision)
        if probability >= SQLI_BLOCK_THRESHOLD:
            abort(403, description="SQL Injection detected")



# ===============================
# Error Handler
# ===============================
@app.errorhandler(403)
def forbidden(e):
    return render_template("sql_error.html"), 403

@app.route("/product/<path:product_name>")
def product(product_name):
    return f"Product: {product_name}"

# ===============================
# Extensions
# ===============================
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth_bp.login_register"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/test-log")
def test_log():
    log_quarantine("test_request", 0.99, "TEST")
    return "logged"

@app.route("/search")
def search():
    return "search page"




# ===============================
# Blueprints
# ===============================
app.register_blueprint(main_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(xss_bp)


# ===============================
# Run
# ===============================
if __name__ == "__main__":
    app.run(debug=True)
