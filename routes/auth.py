from flask import Blueprint, request, render_template, redirect, url_for, flash
from flask_login import login_user, logout_user
from models.user import User
from extensions import db
from security.bruteforce import register_failed_login

auth_bp = Blueprint('auth_bp', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login_register():
    if request.method == 'POST':
        if 'login' in request.form:  # Login form
            email = request.form.get('login-email').strip().lower()
            password = request.form.get('login-password')
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('main_bp.index'))
            else:
                # register failed attempt for this IP + email
                register_failed_login(request.remote_addr or "unknown", email)
                flash('Invalid login credentials')

        elif 'register' in request.form:  # Register form
            username = request.form.get('register-username')
            email = request.form.get('register-email').strip().lower()
            password = request.form.get('register-password')

            if User.query.filter_by(email=email).first():
                flash('Email already registered')
            else:
                num_avatars = 15
                total_users = User.query.count()
                avatar_id = (total_users % num_avatars) + 1
                new_user = User(username=username, email=email)
                new_user.set_password(password)
                db.session.add(new_user)
                db.session.commit()
                flash('Registration successful! Please log in.')

        return redirect(url_for('auth_bp.login_register'))

    return render_template('new_login.html')

@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main_bp.index')) 
