from datetime import datetime
import os

from flask import request, flash, render_template, redirect, make_response, \
    url_for
from flask_login import current_user, login_user, logout_user
from flask_jwt_extended import create_access_token, create_refresh_token, \
    set_access_cookies, unset_jwt_cookies

from qwc_services_core.database import DatabaseEngine
from qwc_config_db.config_models import ConfigModels
from forms import LoginForm


POST_PARAM_LOGIN = os.environ.get("POST_PARAM_LOGIN", default="False")
if POST_PARAM_LOGIN.lower() in ("f", "false"):
    POST_PARAM_LOGIN = False

# max number of failed login attempts before sign in is blocked
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 20))


class DBAuth:
    """DBAuth class

    Provide user login and password reset with local user database.
    """

    def __init__(self, logger):
        """Constructor

        :param Logger logger: Application logger
        """
        self.logger = logger
        self.session_query = None

    def login(self):
        """Authorize user and sign in."""
        target_url = request.args.get('url', '/')
        retry_target_url = request.args.get('url', None)

        if current_user.is_authenticated:
            return redirect(target_url)

        if POST_PARAM_LOGIN:
            username = request.form.get('username')
            password = request.form.get('password')
            if username:
                user = self.user_query().filter_by(name=username).first()
                if self.__user_is_authorized(user, password):
                    return self.__login_response(user, target_url)
                else:
                    self.logger.info(
                        "POST_PARAM_LOGIN: Invalid username or password")
                    return redirect(url_for('login', url=retry_target_url))

        form = LoginForm()
        if form.validate_on_submit():
            user = self.user_query().filter_by(name=form.username.data).first()
            if self.__user_is_authorized(user, form.password.data):
                return self.__login_response(user, target_url)
            else:
                flash('Invalid username or password')
                return redirect(url_for('login', url=retry_target_url))

        return render_template('login.html', title='Sign In', form=form)

    def logout(self):
        """Sign out."""
        target_url = request.args.get('url', '/')
        resp = make_response(redirect(target_url))
        unset_jwt_cookies(resp)
        logout_user()
        return resp

    def load_user(self, id):
        """Load user by id.

        :param int id: User ID
        """
        return self.user_query().get(int(id))

    def user_query(self):
        """Return base user query."""
        if self.session_query is None:
            db_engine = DatabaseEngine()
            config_models = ConfigModels(db_engine)
            user_model = config_models.model('users')
            self.session_query = config_models.session().query(user_model)
        return self.session_query

    def __user_is_authorized(self, user, password):
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
                # update last sign in timestamp and reset failed attempts
                # counter
                user.last_sign_in_at = datetime.utcnow()
                user.failed_sign_in_count = 0
                self.user_query().session.commit()

                return True
            else:
                # block sign in due to too many login attempts
                return False
        else:
            # invalid password

            # increase failed login attempts counter
            user.failed_sign_in_count += 1
            self.user_query().session.commit()

            return False

    def __login_response(self, user, target_url):
        self.logger.info("Logging in as user '%s'" % user.name)
        login_user(user)

        # Create the tokens we will be sending back to the user
        access_token = create_access_token(identity=user.name)
        # refresh_token = create_refresh_token(identity=username)

        resp = make_response(redirect(target_url))
        # Set the JWTs and the CSRF double submit protection cookies
        # in this response
        set_access_cookies(resp, access_token)

        return resp
