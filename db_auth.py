import base64
from datetime import datetime
from io import BytesIO
import os

from flask import abort, flash, make_response, redirect, render_template, \
    request, Response, session, url_for
from flask_login import current_user, login_user, logout_user
from flask_jwt_extended import create_access_token, create_refresh_token, \
    set_access_cookies, unset_jwt_cookies
from flask_mail import Message
import pyotp
import qrcode

from qwc_services_core.database import DatabaseEngine
from qwc_config_db.config_models import ConfigModels
from forms import LoginForm, NewPasswordForm, EditPasswordForm, VerifyForm


POST_PARAM_LOGIN = os.environ.get("POST_PARAM_LOGIN", default="False")
if POST_PARAM_LOGIN.lower() in ("f", "false"):
    POST_PARAM_LOGIN = False

# max number of failed login attempts before sign in is blocked
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 20))

# enable two factor authentication using TOTP
TOTP_ENABLED = os.environ.get('TOTP_ENABLED', 'False') == 'True'

# issuer name for QR code URI
TOTP_ISSUER_NAME = os.environ.get('TOTP_ISSUER_NAME', 'QWC Services')


class DBAuth:
    """DBAuth class

    Provide user login and password reset with local user database.
    """

    # name of default admin user
    DEFAULT_ADMIN_USER = 'admin'

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

        self.clear_verify_session()

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

            # force password change on first sign in of default admin user
            # NOTE: user.last_sign_in_at will be set after successful auth
            force_password_change = (
                user and user.name == self.DEFAULT_ADMIN_USER
                and user.last_sign_in_at is None
            )

            if self.__user_is_authorized(user, form.password.data):
                if not force_password_change:
                    if TOTP_ENABLED:
                        session['login_uid'] = user.id
                        session['target_url'] = target_url
                        if user.totp_secret:
                            # show form for verification token
                            return self.verify(False)
                        else:
                            # show form for TOTP setup on first sign in
                            return self.setup_totp(False)
                    else:
                        # login successful
                        return self.__login_response(user, target_url)
                else:
                    return self.require_password_change(user, target_url)
            else:
                flash('Invalid username or password')
                return redirect(url_for('login', url=retry_target_url))

        return render_template('login.html', title='Sign In', form=form)

    def verify(self, submit=True):
        """Show form for TOTP verification token.

        :param bool submit: Whether form was submitted
                            (False if shown after login form)
        """
        if not TOTP_ENABLED or 'login_uid' not in session:
            # TOTP not enabled or not in login process
            return redirect(url_for('login'))

        user = self.load_user(session.get('login_uid', None))
        if user is None:
            # user not found
            return redirect(url_for('login'))

        form = VerifyForm()
        if submit and form.validate_on_submit():
            if self.user_totp_is_valid(user, form.token.data):
                # TOTP verified
                target_url = session.pop('target_url', '/')
                self.clear_verify_session()
                return self.__login_response(user, target_url)
            else:
                flash('Invalid verification code')
                form.token.errors.append('Invalid verification code')
                form.token.data = None

            if user.failed_sign_in_count >= MAX_LOGIN_ATTEMPTS:
                # redirect to login after too many login attempts
                return redirect(url_for('login'))

        return render_template('verify.html', title='Sign In', form=form)

    def logout(self):
        """Sign out."""
        self.clear_verify_session()
        target_url = request.args.get('url', '/')
        resp = make_response(redirect(target_url))
        unset_jwt_cookies(resp)
        logout_user()
        return resp

    def setup_totp(self, submit=True):
        """Show form with TOTP QR Code and token confirmation.

        :param bool submit: Whether form was submitted
                            (False if shown after login form)
        """
        if not TOTP_ENABLED or 'login_uid' not in session:
            # TOTP not enabled or not in login process
            return redirect(url_for('login'))

        user = self.load_user(session.get('login_uid', None))
        if user is None:
            # user not found
            return redirect(url_for('login'))

        totp_secret = session.get('totp_secret', None)
        if totp_secret is None:
            # generate new secret
            totp_secret = pyotp.random_base32()
            # store temp secret in session
            session['totp_secret'] = totp_secret

        form = VerifyForm()
        if submit and form.validate_on_submit():
            if pyotp.totp.TOTP(totp_secret).verify(
                form.token.data, valid_window=1
            ):
                # TOTP confirmed

                # save TOTP secret
                user.totp_secret = totp_secret
                self.user_query().session.commit()

                target_url = session.pop('target_url', '/')
                self.clear_verify_session()
                return self.__login_response(user, target_url)
            else:
                flash('Invalid verification code')
                form.token.errors.append('Invalid verification code')
                form.token.data = None

        # enable one-time loading of QR code image
        session['show_qrcode'] = True

        # show form
        resp = make_response(render_template(
            'qrcode.html', title='Two Factor Authentication Setup', form=form,
            totp_secret=totp_secret
        ))
        # do not cache in browser
        resp.headers.set(
            'Cache-Control', 'no-cache, no-store, must-revalidate'
        )
        resp.headers.set('Pragma', 'no-cache')
        resp.headers.set('Expires', '0')

        return resp

    def qrcode(self):
        """Return TOTP QR code."""
        if not TOTP_ENABLED or 'login_uid' not in session:
            # TOTP not enabled or not in login process
            abort(404)

        # check presence of show_qrcode
        # to allow one-time loading from TOTP setup form
        if 'show_qrcode' not in session:
            # not in TOTP setup form
            abort(404)
        # remove show_qrcode from session
        session.pop('show_qrcode', None)

        totp_secret = session.get('totp_secret', None)
        if totp_secret is None:
            # temp secret not set
            abort(404)

        user = self.load_user(session.get('login_uid', None))
        if user is None:
            # user not found
            abort(404)

        # generate TOTP URI
        email = user.email or user.name
        uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            email, issuer_name=TOTP_ISSUER_NAME
        )

        # generate QR code
        img = qrcode.make(uri, box_size=6, border=1)
        stream = BytesIO()
        img.save(stream, 'PNG')

        return Response(
                stream.getvalue(),
                content_type='image/png',
                headers={
                    # do not cache in browser
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                },
                status=200
            )

    def new_password(self):
        """Show form and send reset password instructions."""
        form = NewPasswordForm()
        if form.validate_on_submit():
            user = self.user_query().filter_by(email=form.email.data).first()
            if user:
                # generate and save reset token
                user.reset_password_token = self.generate_token()
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
                if user.last_sign_in_at is None:
                    # set last sign in timestamp after required password change
                    # to mark as password changed
                    user.last_sign_in_at = datetime.utcnow()
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

        if token:
            # set hidden field
            form.reset_password_token.data = token

        return render_template(
            'edit_password.html', title='Change your password', form=form
        )

    def require_password_change(self, user, target_url):
        """Show form for required password change.

        :param User user: User instance
        :param str target_url: URL for redirect
        """
        # clear last sign in timestamp and generate reset token
        # to mark as requiring password change
        user.last_sign_in_at = None
        user.reset_password_token = self.generate_token()
        self.user_query().session.commit()

        # show password reset form
        form = EditPasswordForm()
        # set hidden field
        form.reset_password_token.data = user.reset_password_token

        flash("Please choose a new password")
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
                if not TOTP_ENABLED:
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

    def user_totp_is_valid(self, user, token):
        """Check TOTP token, update user sign in fields and
        return whether user is authorized.

        :param User user: User instance
        :param str token: TOTP token
        """
        if user is None or not user.totp_secret:
            # invalid user ID or blank TOTP secret
            return False
        elif pyotp.totp.TOTP(user.totp_secret).verify(token, valid_window=1):
            # valid token
            # update last sign in timestamp and reset failed attempts counter
            user.last_sign_in_at = datetime.utcnow()
            user.failed_sign_in_count = 0
            self.user_query().session.commit()

            return True
        else:
            # invalid token

            # increase failed login attempts counter
            user.failed_sign_in_count += 1
            self.user_query().session.commit()

            return False

    def clear_verify_session(self):
        """Clear session values for TOTP verification."""
        session.pop('login_uid', None)
        session.pop('target_url', None)
        session.pop('totp_secret', None)
        session.pop('show_qrcode', None)

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

    def generate_token(self):
        """Generate new token."""
        token = None
        while token is None:
            # generate token
            token = base64.urlsafe_b64encode(os.urandom(15)). \
                rstrip(b'=').decode('ascii')

            # check uniqueness of token
            if self.find_user_by_token(token):
                # token already present
                token = None

        return token

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
