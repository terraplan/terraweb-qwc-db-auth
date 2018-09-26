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

# https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-v-user-logins
login = LoginManager(app)

jwt = jwt_manager(app)

session_query = None


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
    if current_user.is_authenticated:
        return redirect(target_url)

    if POST_PARAM_LOGIN:
        username = request.form.get('username')
        password = request.form.get('password')
        if username:
            user = user_query().filter_by(name=username).first()
            if user is None or not user.check_password(password):
                app.logger.info(
                    "POST_PARAM_LOGIN: Invalid username or password")
                return redirect(url_for('login'))
            return __login_response(user, target_url)

    form = LoginForm()
    if form.validate_on_submit():
        user = user_query().filter_by(name=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        return __login_response(user, target_url)
    return render_template('login.html', title='Sign In', form=form)


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
