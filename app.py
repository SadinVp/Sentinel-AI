from flask import Flask, request, render_template
from flask_login import LoginManager
import os

from extensions import db
from routes.auth import auth_bp
from routes.main import main_bp
from routes.xssdemo import xss_bp
from models.user import User

from security.bruteforce import bruteforce_waf
from security.global_waf import global_waf_middleware
from security.sqli_waf import sqli_waf_middleware


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
# Paths that correspond to login endpoints
LOGIN_PATHS = ["/login", "/auth/login", "/auth/login_register"]  # adjust to your real routes

@app.before_request
def bruteforce_before_request():
    resp = bruteforce_waf(LOGIN_PATHS)
    if resp is not None:
        return resp



# ===============================
# GLOBAL WAF (Layer 1)
# ===============================
@app.before_request
def global_waf():
    return global_waf_middleware(SAFE_PATHS)


# ===============================
# SQLi WAF (Layer 2)
# ===============================
@app.before_request
def sqli_waf():
    return sqli_waf_middleware(SAFE_PATHS)


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
