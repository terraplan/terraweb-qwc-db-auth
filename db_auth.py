import base64
from datetime import datetime
import os

from flask import request, flash, render_template, redirect, make_response, \
    url_for
from flask_login import current_user, login_user, logout_user
from flask_jwt_extended import create_access_token, create_refresh_token, \
    set_access_cookies, unset_jwt_cookies
from flask_mail import Message

from qwc_services_core.database import DatabaseEngine
from qwc_config_db.config_models import ConfigModels
from forms import LoginForm, NewPasswordForm, EditPasswordForm


POST_PARAM_LOGIN = os.environ.get("POST_PARAM_LOGIN", default="False")
if POST_PARAM_LOGIN.lower() in ("f", "false"):
    POST_PARAM_LOGIN = False

# max number of failed login attempts before sign in is blocked
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 20))


class DBAuth:
    """DBAuth class

    Provide user login and password reset with local user database.
    """

    def __init__(self, mail, logger):
        """Constructor

        :param flask_mail.Mail mail: Application mailer
        :param Logger logger: Application logger
        """
        self.mail = mail
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

    def new_password(self):
        """Show form and send reset password instructions."""
        form = NewPasswordForm()
        if form.validate_on_submit():
            user = self.user_query().filter_by(email=form.email.data).first()
            if user:
                token = None
                while token is None:
                    # generate reset token
                    token = base64.urlsafe_b64encode(os.urandom(15)). \
                        rstrip(b'=').decode('ascii')

                    # check uniqueness of token
                    if self.find_user_by_token(token):
                        # token already present
                        token = None

                # save token
                user.reset_password_token = token
                self.user_query().session.commit()

                # send password reset instructions
                try:
                    self.send_reset_passwort_instructions(user)
                except Exception as e:
                    self.logger.error(
                        "Could not send reset password instructions to "
                        "user '%s':\n%s" % (user.email, e)
                    )
                    flash("Failed to send reset password instructions")
                    return render_template(
                        'new_password.html', title='Forgot your password?',
                        form=form
                    )

            # NOTE: show message anyway even if email not found
            flash(
                "You will receive an email with instructions on how to reset "
                "your password in a few minutes."
            )
            return redirect(url_for('login'))

        return render_template(
            'new_password.html', title='Forgot your password?', form=form
        )

    def edit_password(self, token):
        """Show form and reset password.

        :param str: Password reset token
        """
        form = EditPasswordForm()
        if form.validate_on_submit():
            user = self.find_user_by_token(form.reset_password_token.data)
            if user:
                # save new password
                user.set_password(form.password.data)
                # clear token
                user.reset_password_token = None
                self.user_query().session.commit()

                flash("Your password was changed successfully.")
                return redirect(url_for('login'))
            else:
                # invalid reset token
                flash("Reset password token is invalid")
                return render_template(
                    'edit_password.html', title='Change your password',
                    form=form
                )

        # set hidden field
        form.reset_password_token.data = token

        return render_template(
            'edit_password.html', title='Change your password', form=form
        )

    def load_user(self, id):
        """Load user by id.

        :param int id: User ID
        """
        return self.user_query().get(int(id))

    def find_user_by_token(self, token):
        """Load user by password reset token.

        :param str: Password reset token
        """
        return self.user_query().filter_by(reset_password_token=token).first()

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

    def send_reset_passwort_instructions(self, user):
        """Send mail with reset password instructions to user.

        :param User user: User instance
        """
        # generate full reset password URL
        reset_url = url_for(
            'edit_password', reset_password_token=user.reset_password_token,
            _external=True
        )

        msg = Message(
            "Reset password instructions",
            recipients=[user.email]
        )
        # set message body from template
        msg.body = render_template(
            'reset_password_instructions.txt', user=user, reset_url=reset_url
        )

        # send message
        self.logger.debug(msg)
        self.mail.send(msg)
