Getting Started
===============

An important component is that the Authenticator needs its own set of credentials, as it needs access to the MAuth Server to authenticate requests.

You will need to raise a ticket to register a public key and get an *APP_UUID* for the environment of your application.  Note that the *MAUTH_BASE_URL* will probably
include the environment, e.g. *https://mauth-sandbox.imedidata.net*


Installation
------------

Install using pip::

    $ pip install flask-mauth


Or directly from GitHub::

    $ pip install git+https://github.com/mdsol/flask-mauth.git

This will also install the dependencies

Usage
-----

To use *Flask-MAuth* you will need to create an application instance and supply the required configuration options::

    from flask import Flask
    from flask_mauth import MAuthAuthenticator

    app = Flask("Some Sample App")
    app.config['MAUTH_APP_UUID'] = '671785CD-15CE-458A-9779-8132C8F60F04'   # This will be the APP UUID for your application
    app.config['MAUTH_KEY_DATA'] = key_text                                 # This will be the content of the Private Key
    app.config['MAUTH_BASE_URL'] = "https://mauth-sandbox.imedidata.net"    # The MAuth Server Base URL
    app.config['MAUTH_VERSION'] = "v2"                                      # This defaults to v2 and can be left out
    app.config['MAUTH_MODE'] = "local"                                      # This should be either 'local' or 'remote'
    mauth = MAuthAuthenticator()
    mauth.init_app(app)

To specify routes that need to be authenticated use the `requires_authentication` decorator::

    from flask_mauth import MAuthAuthenticator, requires_authentication
    @app.route("/some/private/route", methods=["GET"])
    @requires_authentication
    def private_route():
        return 'Wibble'

    @app.route("/app_status", methods=["GET"])
    def app_status():
        return 'OK'



