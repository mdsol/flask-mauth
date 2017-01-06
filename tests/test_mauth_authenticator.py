# -*- coding: utf-8 -*-
import json
import unittest

import mock
from flask import Flask

from flask_mauth.auth import MAuthAuthenticator, requires_authentication
from tests.common import load_key


class MAuthAthenticatorTestCase(unittest.TestCase):

    def setUp(self):
        self.app = Flask("Test App")

    def test_app_configuration(self):
        """With everything present, initialisation of app is ok"""
        key_text = load_key('priv')
        self.app.config['MAUTH_APP_UUID'] = '671785CD-15CE-458A-9779-8132C8F60F04'
        self.app.config['MAUTH_KEY_DATA'] = key_text
        self.app.config['MAUTH_BASE_URL'] = "https://mauth-sandbox.imedidata.net"
        self.app.config['MAUTH_VERSION'] = "v2"
        self.app.config['MAUTH_MODE'] = "local"
        try:
            authenticator = MAuthAuthenticator(self.app)
        except TypeError as exc:
            self.fail("Shouldn't raise an exception")

    def test_app_configuration_missing_uuid(self):
        """With APP_UUID missing, initialisation of app is wrong"""
        key_text = load_key('priv')
        self.app.config['MAUTH_KEY_DATA'] = key_text
        self.app.config['MAUTH_BASE_URL'] = "https://mauth-sandbox.imedidata.net"
        self.app.config['MAUTH_VERSION'] = "v2"
        self.app.config['MAUTH_MODE'] = "local"
        with self.assertRaises(TypeError) as exc:
            authenticator = MAuthAuthenticator(self.app)
        self.assertEqual(str(exc.exception),
                         "MAuthAuthenticator requires both a MAUTH_APP_UUID and MAUTH_KEY_DATA to be set")

    def test_app_configuration_missing_key(self):
        """With Key Text missing, initialisation of app is wrong"""
        key_text = load_key('priv')
        self.app.config['MAUTH_APP_UUID'] = '671785CD-15CE-458A-9779-8132C8F60F04'
        self.app.config['MAUTH_BASE_URL'] = "https://mauth-sandbox.imedidata.net"
        self.app.config['MAUTH_VERSION'] = "v2"
        self.app.config['MAUTH_MODE'] = "local"
        with self.assertRaises(TypeError) as exc:
            authenticator = MAuthAuthenticator(self.app)
        self.assertEqual(str(exc.exception),
                         "MAuthAuthenticator requires both a MAUTH_APP_UUID and MAUTH_KEY_DATA to be set")

    def test_app_configuration_missing_base_url(self):
        """With BASE_URL missing, initialisation of app is wrong"""
        key_text = load_key('priv')
        self.app.config['MAUTH_APP_UUID'] = '671785CD-15CE-458A-9779-8132C8F60F04'
        self.app.config['MAUTH_KEY_DATA'] = key_text
        self.app.config['MAUTH_VERSION'] = "v2"
        self.app.config['MAUTH_MODE'] = "local"
        with self.assertRaises(TypeError) as exc:
            authenticator = MAuthAuthenticator(self.app)
        self.assertEqual(str(exc.exception),
                         "MAuthAuthenticator requires a MAUTH_BASE_URL and MAUTH_VERSION")

    def test_app_configuration_missing_version(self):
        """With VERSION missing, initialisation of app is ok"""
        key_text = load_key('priv')
        self.app.config['MAUTH_APP_UUID'] = '671785CD-15CE-458A-9779-8132C8F60F04'
        self.app.config['MAUTH_KEY_DATA'] = key_text
        self.app.config['MAUTH_BASE_URL'] = "https://mauth-sandbox.imedidata.net"
        self.app.config['MAUTH_MODE'] = "local"
        try:
            authenticator = MAuthAuthenticator(self.app)
        except TypeError as exc:
            self.fail("Shouldn't raise an exception")
        self.assertEqual('v2', authenticator.mauth_version)

    def test_app_configuration_wrong_mode(self):
        """With incorrect mode, initialisation of app is wrong"""
        key_text = load_key('priv')
        self.app.config['MAUTH_APP_UUID'] = '671785CD-15CE-458A-9779-8132C8F60F04'
        self.app.config['MAUTH_KEY_DATA'] = key_text
        self.app.config['MAUTH_BASE_URL'] = "https://mauth-sandbox.imedidata.net"
        self.app.config['MAUTH_MODE'] = "banana"
        with self.assertRaises(TypeError) as exc:
            authenticator = MAuthAuthenticator(self.app)
        self.assertEqual(str(exc.exception),
                         "MAuthAuthenticator MAUTH_MODE must be one of local or remote")

    def test_app_configuration_remote(self):
        """With remote mode, initialisation of app is ok"""
        key_text = load_key('priv')
        self.app.config['MAUTH_APP_UUID'] = '671785CD-15CE-458A-9779-8132C8F60F04'
        self.app.config['MAUTH_KEY_DATA'] = key_text
        self.app.config['MAUTH_BASE_URL'] = "https://mauth-sandbox.imedidata.net"
        self.app.config['MAUTH_MODE'] = "remote"
        try:
            authenticator = MAuthAuthenticator(self.app)
        except TypeError as exc:
            self.fail("Shouldn't raise an exception")
        self.assertEqual('remote', authenticator.mauth_mode)

    def test_app_configuration_and_call_protected_url(self):
        """A protected route will raise if the call is inauthentic"""
        key_text = load_key('priv')
        self.app.config['MAUTH_APP_UUID'] = '671785CD-15CE-458A-9779-8132C8F60F04'
        self.app.config['MAUTH_KEY_DATA'] = key_text
        self.app.config['MAUTH_BASE_URL'] = "https://mauth-sandbox.imedidata.net"
        self.app.config['MAUTH_VERSION'] = "v2"
        self.app.config['MAUTH_MODE'] = "local"
        authenticator = MAuthAuthenticator()
        authenticator.init_app(self.app)

        @self.app.route("/", methods=['GET'])
        @requires_authentication
        def test_url_closed():
            return "Ping"

        client = self.app.test_client()

        # protected URL
        rv = client.get("/")
        self.assertEqual(401, rv.status_code)
        self.assertEqual(dict(errors=dict(mauth=["Authentication Failed. No mAuth signature present; "
                                                 "X-MWS-Authentication header is blank."])),
                         json.loads(rv.data.decode('utf-8')))

    def test_app_configuration_and_call_open_url(self):
        """An open route will pass"""
        key_text = load_key('priv')
        self.app.config['MAUTH_APP_UUID'] = '671785CD-15CE-458A-9779-8132C8F60F04'
        self.app.config['MAUTH_KEY_DATA'] = key_text
        self.app.config['MAUTH_BASE_URL'] = "https://mauth-sandbox.imedidata.net"
        self.app.config['MAUTH_VERSION'] = "v2"
        self.app.config['MAUTH_MODE'] = "local"
        authenticator = MAuthAuthenticator()
        authenticator.init_app(self.app)

        @self.app.route("/lemon", methods=['GET'])
        def test_url_open():
            return "Ping"

        client = self.app.test_client()

        # open URL
        rv = client.get("/lemon")
        self.assertEqual(200, rv.status_code)
        self.assertEqual(b'Ping', rv.data)

    def test_app_configuration_with_valid_call(self):
        """If the call is authenticated then the call will get passed"""
        key_text = load_key('priv')
        self.app.config['MAUTH_APP_UUID'] = '671785CD-15CE-458A-9779-8132C8F60F04'
        self.app.config['MAUTH_KEY_DATA'] = key_text
        self.app.config['MAUTH_BASE_URL'] = "https://mauth-sandbox.imedidata.net"
        self.app.config['MAUTH_VERSION'] = "v2"
        self.app.config['MAUTH_MODE'] = "local"

        @self.app.route("/", methods=['GET'])
        @requires_authentication
        def test_url_closed():
            return "Ping"

        client = self.app.test_client()

        with mock.patch("flask_mauth.auth.LocalAuthenticator") as local_auth:
            m_auth = local_auth.return_value
            m_auth.is_authentic.return_value = True, 200, ""
            authenticator = MAuthAuthenticator()
            authenticator.init_app(self.app)
            # protected URL
            rv = client.get("/")
            self.assertEqual(200, rv.status_code)
            self.assertEqual(b'Ping', rv.data)
