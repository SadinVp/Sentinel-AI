from flask import Flask, request, abort, render_template
from flask_login import LoginManager
from extensions import db
from routes.auth import auth_bp
from routes.main import main_bp
from models.user import User
from routes.xssdemo import xss_bp
import joblib


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Dinu2004@localhost/sentinel_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

model = joblib.load('models/sqli_model.joblib')
vectorizer = joblib.load('models/sqli_vectorizer.joblib')
@app.before_request
def waf_middleware():
    for key, value in {**request.args, **request.form}.items():
        input_vectorized = vectorizer.transform([value])
        prediction = model.predict(input_vectorized)
        if prediction[0] == 1:
            abort(403, description="Malicious request detected and blocked by Sentinel AI.")

@app.errorhandler(403)
def forbidden(e):
    return render_template('sql_error.html'), 403


db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth_bp.login_register'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Register the Blueprints here
app.register_blueprint(main_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(xss_bp)



if __name__ == "__main__":
    app.run(debug=True)