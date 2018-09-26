Authentication with User DB
===========================

Authentication service with local user database.


Configuration
-------------

Besides the form based DB login, an (insecure) plain POST login is supported. This method can be
activated by setting `POST_PARAM_LOGIN=True`. User and password are passed as POST parameters 
`username` and `password`.
Usage example: `curl -d 'username=demo&password=demo' http://localhost:5017/login`.


Usage
-----

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
