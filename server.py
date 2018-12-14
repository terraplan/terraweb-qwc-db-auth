from datetime import datetime
import os
import sys

from flask import Flask, jsonify, request, flash, render_template, redirect, \
    make_response, url_for
from flask_login import LoginManager, current_user, login_user, logout_user
from flask_jwt_extended import (
    jwt_required, jwt_optional, create_access_token,
    jwt_refresh_token_required, create_refresh_token, get_csrf_token,
    get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies
)
from flask_mail import Mail
from forms import LoginForm
from qwc_services_core.jwt import jwt_manager
from qwc_services_core.database import DatabaseEngine
from qwc_config_db.config_models import ConfigModels

app = Flask(__name__)

app.secret_key = os.environ.get(
        'JWT_SECRET_KEY',
        'CHANGE-ME-1ef43ade8807dc37a6588cb8fb9dec4caf6dfd0e00398f9a')

POST_PARAM_LOGIN = os.environ.get("POST_PARAM_LOGIN", default="False")
if POST_PARAM_LOGIN.lower() in ("f", "false"):
    POST_PARAM_LOGIN = False

# max number of failed login attempts before sign in is blocked
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 20))

# https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-v-user-logins
login = LoginManager(app)

jwt = jwt_manager(app)

session_query = None


def mail_config_from_env(app):
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', '127.0.0.1')
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 25))
    app.config['MAIL_USE_TLS'] = os.environ.get(
        'MAIL_USE_TLS', 'False') == 'True'
    app.config['MAIL_USE_SSL'] = os.environ.get(
        'MAIL_USE_SSL', 'False') == 'True'
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
    app.config['MAIL_DEBUG'] = int(os.environ.get('MAIL_DEBUG', app.debug))
    app.config['MAIL_MAX_EMAILS'] = os.environ.get('MAIL_MAX_EMAILS')
    app.config['MAIL_SUPPRESS_SEND'] = os.environ.get(
        'MAIL_SUPPRESS_SEND', str(app.testing)) == 'True'
    app.config['MAIL_ASCII_ATTACHMENTS'] = os.environ.get(
        'MAIL_ASCII_ATTACHMENTS', False)


mail_config_from_env(app)
mail = Mail(app)


def user_query():
    global session_query
    if session_query is None:
        db_engine = DatabaseEngine()
        config_models = ConfigModels(db_engine)
        user_model = config_models.model('users')
        session_query = config_models.session().query(user_model)
    return session_query


@login.user_loader
def load_user(id):
    return user_query().get(int(id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    target_url = request.args.get('url', '/')
    retry_target_url = request.args.get('url', None)

    if current_user.is_authenticated:
        return redirect(target_url)

    if POST_PARAM_LOGIN:
        username = request.form.get('username')
        password = request.form.get('password')
        if username:
            user = user_query().filter_by(name=username).first()
            if __user_is_authorized(user, password):
                return __login_response(user, target_url)
            else:
                app.logger.info(
                    "POST_PARAM_LOGIN: Invalid username or password")
                return redirect(url_for('login', url=retry_target_url))

    form = LoginForm()
    if form.validate_on_submit():
        user = user_query().filter_by(name=form.username.data).first()
        if __user_is_authorized(user, form.password.data):
            return __login_response(user, target_url)
        else:
            flash('Invalid username or password')
            return redirect(url_for('login', url=retry_target_url))

    return render_template('login.html', title='Sign In', form=form)


def __user_is_authorized(user, password):
    """Check credentials, update user sign in fields and
    return whether user is authorized.

    :param User user: User instance
    :param str password: Password
    """
    if user is None:
        # invalid username
        return False
    elif user.check_password(password):
        # valid credentials
        if user.failed_sign_in_count < MAX_LOGIN_ATTEMPTS:
            # update last sign in timestamp and reset failed attempts counter
            user.last_sign_in_at = datetime.utcnow()
            user.failed_sign_in_count = 0
            user_query().session.commit()

            return True
        else:
            # block sign in due to too many login attempts
            return False
    else:
        # invalid password

        # increase failed login attempts counter
        user.failed_sign_in_count += 1
        user_query().session.commit()

        return False


def __login_response(user, target_url):
    app.logger.info("Logging in as user '%s'" % user.name)
    login_user(user)

    # Create the tokens we will be sending back to the user
    access_token = create_access_token(identity=user.name)
    # refresh_token = create_refresh_token(identity=username)

    resp = make_response(redirect(target_url))
    # Set the JWTs and the CSRF double submit protection cookies
    # in this response
    set_access_cookies(resp, access_token)

    return resp


@app.route('/logout', methods=['GET', 'POST'])
@jwt_required
def logout():
    target_url = request.args.get('url', '/')
    resp = make_response(redirect(target_url))
    unset_jwt_cookies(resp)
    logout_user()
    return resp


if __name__ == '__main__':
    app.run(host='localhost', port=5017, debug=True)
