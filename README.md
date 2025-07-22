TERRAWEB-QWC-DB-AUTH
================================

TERRAWEB-QWC-DB-AUTH is a Flask web framework with the "uv" package manager.

**This repository is based on the [qwc-db-auth](https://github.com/qwc-services/qwc-db-auth).**

# Quick start

1. Go to the official Python downloads page and download the latest Python 3 version for Windows. Crucially, ensure the "Add Python to PATH" option is checked during installation. This allows you to run Python from the command line in any directory. 

2. Install uv:

    pip install uv

3. Verify installation:
    
    python --version
    uv --version

4. Clone the repository:

    git clone https://github.com/terraplan/terraweb-qwc-db-auth.git

5. Install dependencies:

    cd terraweb-qwc-db-auth
    uv sync 

6. Create dbAuthConfig.json and pg_service.conf file: This is only required for local setup. In server this is all setup in the docker environment.

    Copy the file `.dbAuthConfig.json.template` to `.dbAuthConfig.json` anywhere in your filesystem. No need to change anything here.
    Copy the file `.pg_service.conf.template` to `.pg_service.conf` anywhere in your filesystem and adjust your database information.
  
7. Create .flaskenv file: This is only required for local setup. In server the volumes/config folder is where the qwc-docker gets its configuration. The `PGSERVICEFILE=` config is needed in local because we are not using qwc-docker right now so for flask python code to connect to my local database.

       Copy the file `.flaskenv.template` to `.flaskenv` and adjust to your local setup, especially set `CONFIG_PATH=` & `PGSERVICEFILE=` to the file path from step 6. 
       Remember for `CONFIG_PATH=` it is folder path not file path.

8. Create .env file:

       Copy the file `.env.template` to `.env` and set `AUTH_URL=` to TerraWeb authentication URL.

9. Setup database:

    Open pgadmin and create a database `qwc_configdb` > Restore backup file > But before you need to create `qwc_admin` Login/Group Roles in pgadmin.

10. Start local service: 

    uv run src/server.py

    Endpoints:

    http://localhost:5017/login

    http://localhost:5017/logout

See [qwc-db-auth](https://github.com/qwc-services/qwc-db-auth) for further information.