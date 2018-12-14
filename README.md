Authentication with User DB
===========================

Authentication service with local user database.


Configuration
-------------

Besides the form based DB login, an (insecure) plain POST login is supported. This method can be
activated by setting `POST_PARAM_LOGIN=True`. User and password are passed as POST parameters 
`username` and `password`.
Usage example: `curl -d 'username=demo&password=demo' http://localhost:5017/login`.

[Flask-Mail](https://pythonhosted.org/Flask-Mail/) is used for sending mails like password resets. These are the available options:
* `MAIL_SERVER`: default ‘localhost’
* `MAIL_PORT`: default 25
* `MAIL_USE_TLS`: default False
* `MAIL_USE_SSL`: default False
* `MAIL_DEBUG`: default app.debug
* `MAIL_USERNAME`: default None
* `MAIL_PASSWORD`: default None
* `MAIL_DEFAULT_SENDER`: default None
* `MAIL_MAX_EMAILS`: default None
* `MAIL_SUPPRESS_SEND`: default app.testing
* `MAIL_ASCII_ATTACHMENTS`: default False

In addition the standard Flask `TESTING` configuration option is used by Flask-Mail in unit tests.

Usage
-----

Set the `MAX_LOGIN_ATTEMPTS` environment variable to set the maximum number of 
failed login attempts before sign in is blocked (default: `20`).

Run standalone application:

    python server.py

Endpoints:

    http://localhost:5017/login

    http://localhost:5017/logout


Development
-----------

Create a virtual environment:

    virtualenv --python=/usr/bin/python3 .venv

Activate virtual environment:

    source .venv/bin/activate

Install requirements:

    pip install -r requirements.txt

Start local service:

    python server.py
