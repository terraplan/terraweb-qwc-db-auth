import os

from flask import Flask
from flask_login import LoginManager
from flask_jwt_extended import jwt_required, jwt_optional
from flask_mail import Mail

from qwc_services_core.jwt import jwt_manager
from db_auth import DBAuth


app = Flask(__name__)

app.secret_key = os.environ.get(
        'JWT_SECRET_KEY',
        'CHANGE-ME-1ef43ade8807dc37a6588cb8fb9dec4caf6dfd0e00398f9a')

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

# create DB auth
db_auth = DBAuth(app.logger)

@login.user_loader
def load_user(id):
    return db_auth.load_user(id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    return db_auth.login()


@app.route('/logout', methods=['GET', 'POST'])
@jwt_required
def logout():
    return db_auth.logout()


if __name__ == '__main__':
    app.run(host='localhost', port=5017, debug=True)
