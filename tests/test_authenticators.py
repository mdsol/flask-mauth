# -*- coding: utf-8 -*-

import datetime
import json
import time
from unittest import TestCase

import requests_mauth
import mock
from mock import patch
from six import assertRegex

from flask_mauth.mauth.authenticators import LocalAuthenticator, AbstractMAuthAuthenticator, RemoteAuthenticator, \
    mws_attr
from flask_mauth import settings
from flask_mauth.exceptions import InauthenticError, UnableToAuthenticateError
from tests.common import load_key


class _TestAuthenticator(object):
    """
    Pseudo-abstract base class for the Test Cases
    """

    def test_authentication_present_happy_path(self):
        """With the header present, we are ok"""
        request = mock.Mock(headers={settings.x_mws_authentication: 'MWS 1234'})
        self.assertTrue(self.authenticator.authentication_present(request))

    def test_authentication_present_missing(self):
        """With the header missing we throw an exception"""
        request = mock.Mock(headers={})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.authentication_present(request)
        self.assertEqual(str(exc.exception),
                         "Authentication Failed. No mAuth signature present; X-MWS-Authentication header is blank.",
                         )

    def test_authentication_present_blank(self):
        """With the header present but blank we throw an exception"""
        request = mock.Mock(headers={settings.x_mws_authentication: ''})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.authentication_present(request)
        self.assertEqual(str(exc.exception),
                         "Authentication Failed. No mAuth signature present; X-MWS-Authentication header is blank."
                         )

    def test_time_valid_happy_path(self):
        """With an ok time, we are ok"""
        now = int(time.time())
        request = mock.Mock(headers={settings.x_mws_time: '%s' % now})
        self.assertTrue(self.authenticator.time_valid(request=request))

    def test_time_valid_missing_header(self):
        """With a missing header, we get an exception"""
        request = mock.Mock(headers={})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.time_valid(request=request)
        self.assertEqual(str(exc.exception),
                         "Time verification failed for Mock. No x-mws-time present.",
                         )

    def test_time_valid_invalid_header(self):
        """With an invalid header, we get an exception"""
        request = mock.Mock(headers={settings.x_mws_time: 'apple'})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.time_valid(request=request)
        self.assertEqual(str(exc.exception),
                         "Time verification failed for Mock. X-MWS-Time Header format incorrect.",
                         )

    def test_time_valid_empty_header(self):
        """With an empty header, we get an exception"""
        request = mock.Mock(headers={settings.x_mws_time: ''})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.time_valid(request=request)
        self.assertEqual(str(exc.exception),
                         "Time verification failed for Mock. No x-mws-time present.",
                         )

    def test_time_valid_expired_header(self):
        """With an empty header, we get an exception"""
        now = int(time.time()) - (AbstractMAuthAuthenticator.ALLOWED_DRIFT_SECONDS * 100 + 1)
        request = mock.Mock(headers={settings.x_mws_time: str(now)})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.time_valid(request=request)
        assertRegex(self,
                    str(exc.exception),
                    r"Time verification failed for Mock. %s "
                    "not within %ss of [0-9\-]{10} [0-9\:]{7}" % (datetime.datetime.fromtimestamp(now),
                                                                  AbstractMAuthAuthenticator.ALLOWED_DRIFT_SECONDS),
                    )

    def test_token_valid_happy_path(self):
        """With an expected header, all good"""
        request = mock.Mock(headers={settings.x_mws_authentication: 'MWS some-uuid:some hash'})
        self.assertTrue(self.authenticator.token_valid(request))

    def test_token_valid_invalid_token(self):
        """Invalid token leads to exception"""
        request = mock.Mock(headers={settings.x_mws_authentication: 'RWS some-uuid:some hash'})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.token_valid(request)
        self.assertEqual(str(exc.exception),
                         "Token verification failed for Mock. Expected MWS; token was RWS"
                         )

    def test_token_valid_bad_format(self):
        """Badly formatted signature leads to exception"""
        request = mock.Mock(headers={settings.x_mws_authentication: 'MWS'})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.token_valid(request)
        self.assertEqual(str(exc.exception),
                         "Token verification failed for Mock. Misformatted Signature.")

    def test_log_mauth_service_response_error(self):
        """We log an error for a service error"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        response = mock.Mock(status_code=500, data="Upstream Resource unavailable")
        with self.assertRaises(UnableToAuthenticateError) as exc:
            self.authenticator.log_mauth_service_response_error(request, response)
        error = self.logger.error
        error.assert_called_with('MAuth Service: App UUID: {app_uuid}; URL: {url}; '
                                 'MAuth service responded with {status}: {body}'.format(app_uuid=self.app_uuid,
                                                                                        url="/mauth/v2/mauth"
                                                                                            ".json?open=1",
                                                                                        status=500,
                                                                                        body="Upstream Resource "
                                                                                             "unavailable"))

    def test_log_inauthentic_error(self):
        """We log an error for an InAuthentic error"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        self.authenticator.log_authentication_error(request, message="X-MWS-Time too old")
        error = self.logger.error
        error.assert_called_with('MAuth Authentication Error: App UUID: {app_uuid}; URL: {url}; '
                                 'Error: {message}'.format(app_uuid=self.app_uuid,
                                                           url="/mauth/v2/mauth"
                                                               ".json?open=1",
                                                           message="X-MWS-Time too old"))

    def test_log_inauthentic_error_missing_app_uuid(self):
        """We log an error for an InAuthentic error"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.mauth.authenticators.mws_attr") as matt:
            matt.return_value = "", "", "", ""
            self.authenticator.log_authentication_error(request, message="X-MWS-Time too old")
        error = self.logger.error
        error.assert_called_with('MAuth Authentication Error: App UUID: {app_uuid}; URL: {url}; '
                                 'Error: {message}'.format(app_uuid="MISSING",
                                                           url="/mauth/v2/mauth"
                                                               ".json?open=1",
                                                           message="X-MWS-Time too old"))

    def test_log_authorisation_request_info(self):
        """We log an info for a request"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        self.authenticator.log_authentication_request(request)
        info = self.logger.info
        info.assert_called_with('MAuth Request: App UUID: {app_uuid}; URL: {url}'.format(app_uuid=self.app_uuid,
                                                                                         url="/mauth/v2/mauth"
                                                                                             ".json?open=1"))

    def test_log_authorisation_request_missing_app_uuid(self):
        """We log an info for a request, if the APP_UUID is missing we flag"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.mauth.authenticators.mws_attr") as matt:
            matt.return_value = "", "", "", ""
            self.authenticator.log_authentication_request(request)
            info = self.logger.info
        info.assert_called_with('MAuth Request: App UUID: {app_uuid}; URL: {url}'.format(app_uuid="MISSING",
                                                                                         url="/mauth/v2/mauth"
                                                                                             ".json?open=1"))


class TestRemoteAuthenticator(_TestAuthenticator, TestCase):
    """
    Remotely authenticate a request
    """

    def setUp(self):
        self.logger = mock.Mock()
        self.authenticator = RemoteAuthenticator(mauth_auth=mock.Mock(),
                                                 logger=self.logger,
                                                 mauth_api_version='v2',
                                                 mauth_base_url='https://mauth-sandbox.imedidata.net')
        self.mws_time = "1479392498"
        self.app_uuid = 'b0603e5c-c344-488e-83ba-9290ea8dc17d'

    def test_signature_valid(self):
        """ With a valid request we get a 200 response """
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.mauth.authenticators.requests") as req:
            req.post.return_value = mock.Mock(status_code=200)
            result = self.authenticator.signature_valid(request=request)
        self.assertTrue(result)

    def test_signature_invalid_412(self):
        """ With a valid request we get a 412 response """
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.mauth.authenticators.requests") as req:
            req.post.return_value = mock.Mock(status_code=412, content="Blurgle")
            with self.assertRaises(InauthenticError) as exc:
                result = self.authenticator.signature_valid(request=request)
            self.assertEqual(str(exc.exception),
                             "The mAuth service responded with 412: Blurgle")

    def test_signature_invalid_404(self):
        """ With a valid request we get a 412 response """
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.mauth.authenticators.requests") as req:
            req.post.return_value = mock.Mock(status_code=404, content="Blargle")
            with self.assertRaises(InauthenticError) as exc:
                result = self.authenticator.signature_valid(request=request)
            self.assertEqual(str(exc.exception),
                             "The mAuth service responded with 404: Blargle")

    def test_upstream_error(self):
        """ With a mauth server problem """
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.mauth.authenticators.requests") as req:
            req.post.return_value = mock.Mock(status_code=500, data="Urgle")
            with self.assertRaises(UnableToAuthenticateError) as exc:
                result = self.authenticator.signature_valid(request=request)
            self.assertEqual(str(exc.exception),
                             "MAuth Service: App UUID: b0603e5c-c344-488e-83ba-9290ea8dc17d; "
                             "URL: /mauth/v2/mauth.json?open=1; MAuth service responded with 500: Urgle")

    @patch.object(RemoteAuthenticator, "authenticate")
    def test_is_authentic_all_ok(self, authenticate):
        """We get a True back if all tests pass"""
        authenticate.return_value = True
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertTrue(authentic)
        self.assertEqual(200, status)
        self.assertEqual('', message)

    @patch.object(RemoteAuthenticator, "authenticate")
    def test_is_authentic_fails(self, authenticate):
        """We get a False back if one or more tests fail"""
        authenticate.return_value = False
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)
        self.assertEqual(401, status)

    @patch.object(RemoteAuthenticator, "authenticate")
    def test_authenticate_error_conditions_inauthentic(self, authenticate):
        """ We get a False back if we raise a InauthenticError """
        authenticate.side_effect = InauthenticError("Authentication Failed. No mAuth signature present; "
                                                    "X-MWS-Authentication header is blank.")
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)
        self.assertEqual(401, status)
        self.assertEqual("Authentication Failed. No mAuth signature present; "
                                                    "X-MWS-Authentication header is blank.", message)

    @patch.object(RemoteAuthenticator, "authenticate")
    def test_authenticate_error_conditions_unable(self, authenticate):
        """ We get a False back if we raise a UnableToAuthenticateError """
        authenticate.side_effect = UnableToAuthenticateError("")
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)
        self.assertEqual(500, status)
        self.assertEqual("", message)

    @patch.object(RemoteAuthenticator, "signature_valid")
    @patch.object(RemoteAuthenticator, "authentication_present")
    @patch.object(RemoteAuthenticator, "time_valid")
    @patch.object(RemoteAuthenticator, "token_valid")
    def test_is_authentic_some_token_invalid(self, token_valid, time_valid, authentication_present, signature_valid):
        """RemoteAuthenticator: We get a False back if token invalid"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        token_valid.side_effect = InauthenticError("")
        time_valid.return_value = True
        authentication_present.return_value = True
        signature_valid.return_value = True
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)
        self.assertEqual(401, status)
        self.assertEqual("", message)

    @patch.object(RemoteAuthenticator, "signature_valid")
    @patch.object(RemoteAuthenticator, "authentication_present")
    @patch.object(RemoteAuthenticator, "time_valid")
    @patch.object(RemoteAuthenticator, "token_valid")
    def test_is_authentic_some_time_invalid(self, token_valid, time_valid, authentication_present, signature_valid):
        """RemoteAuthenticator: We get a False back if time invalid"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        token_valid.return_value = True
        time_valid.side_effect = InauthenticError("")
        authentication_present.return_value = True
        signature_valid.return_value = True
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)
        self.assertEqual(401, status)
        self.assertEqual("", message)

    @patch.object(RemoteAuthenticator, "signature_valid")
    @patch.object(RemoteAuthenticator, "authentication_present")
    @patch.object(RemoteAuthenticator, "time_valid")
    @patch.object(RemoteAuthenticator, "token_valid")
    def test_is_authentic_some_authentication_missing(self, token_valid, time_valid, authentication_present,
                                                      signature_valid):
        """RemoteAuthenticator: We get a False back if mauth missing"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")

        token_valid.return_value = True
        time_valid.return_value = True
        authentication_present.side_effect = InauthenticError("")
        signature_valid.return_value = True
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)
        self.assertEqual(401, status)
        self.assertEqual("", message)

    @patch.object(RemoteAuthenticator, "signature_valid")
    @patch.object(RemoteAuthenticator, "authentication_present")
    @patch.object(RemoteAuthenticator, "time_valid")
    @patch.object(RemoteAuthenticator, "token_valid")
    def test_is_authentic_some_signature_invalid(self, token_valid, time_valid, authentication_present,
                                                 signature_valid):
        """RemoteAuthenticator: We get a False back if signature invalid"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        token_valid.return_value = True
        time_valid.return_value = True
        authentication_present.return_value = True
        signature_valid.side_effect = InauthenticError("")
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)
        self.assertEqual(401, status)
        self.assertEqual("", message)

    @patch.object(RemoteAuthenticator, "signature_valid")
    @patch.object(RemoteAuthenticator, "authentication_present")
    @patch.object(RemoteAuthenticator, "time_valid")
    @patch.object(RemoteAuthenticator, "token_valid")
    def test_authenticate_is_ok(self, token_valid, time_valid, authentication_present, signature_valid):
        """RemoteAuthenticator:  We get a True back if all tests pass"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        token_valid.return_value = True
        time_valid.return_value = True
        authentication_present.return_value = True
        signature_valid.return_value = True
        authentic = self.authenticator.authenticate(request)
        self.assertTrue(authentic)

    @patch.object(RemoteAuthenticator, "signature_valid")
    @patch.object(RemoteAuthenticator, "authentication_present")
    @patch.object(RemoteAuthenticator, "time_valid")
    @patch.object(RemoteAuthenticator, "token_valid")
    def test_authenticate_fails(self, token_valid, time_valid, authentication_present, signature_valid):
        """RemoteAuthenticator:  We get a False back if any tests fail"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        token_valid.return_value = True
        time_valid.return_value = True
        authentication_present.return_value = True
        signature_valid.return_value = False
        authentic = self.authenticator.authenticate(request)
        self.assertFalse(authentic)

    def test_authentication_type(self):
        """We self-describe"""
        self.assertEqual('REMOTE', self.authenticator.authenticator_type)



class TestLocalAuthenticator(_TestAuthenticator, TestCase):
    def setUp(self):
        self.logger = mock.Mock()
        self.authenticator = LocalAuthenticator(mauth_auth=mock.Mock(),
                                                logger=self.logger,
                                                mauth_api_version='v2',
                                                mauth_base_url='https://mauth-sandbox.imedidata.net')
        self.mws_time = "1479392498"
        self.app_uuid = 'b0603e5c-c344-488e-83ba-9290ea8dc17d'

    def generate_headers(self, verb, path, body, mws_time=None, app_uuid=None):
        """
        Generates a Signature String
        :param verb: HTTP verb, eg GET
        :param path: URL Path (without query strings)
        :param body: Body of request
        :param time:
        :param app_uuid:
        :return:
        """
        if mws_time is None:
            mws_time = self.mws_time
        if app_uuid is None:
            app_uuid = self.app_uuid
        signer = requests_mauth.MAuth(app_uuid=app_uuid, private_key_data=load_key('priv'))
        signature_string, seconds_since_epoch = signer.make_signature_string(verb=verb, url_path=path, body=body,
                                                                             seconds_since_epoch=mws_time)
        signed_string = signer.signer.sign(signature_string)
        auth_headers = signer.make_authentication_headers(signed_string, mws_time)
        return auth_headers

    def test_authenticates_a_genuine_message(self):
        """Given an authentic message, we authenticate"""
        mws_time = int(time.time())
        headers = self.generate_headers("GET",
                                        "/mauth/v2/mauth.json",
                                        "",
                                        mws_time)
        request = mock.Mock(headers=headers,
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.mauth.authenticators.SecurityTokenCacher") as tok:
            cacher = tok.return_value
            cacher.get.return_value = dict(app_name="Apple",
                                           app_uuid=self.app_uuid,
                                           security_token=dict(public_key_str=load_key('pub')),
                                           created_at="2016-11-20 12:08:46 UTC")
            authenticator = LocalAuthenticator(mauth_auth=mock.Mock(),
                                               logger=mock.Mock(),
                                               mauth_api_version='v2',
                                               mauth_base_url='https://mauth-sandbox.imedidata.net')

            result = authenticator.signature_valid(request)
        self.assertTrue(result)

    def test_authentication_type(self):
        """We self-describe"""
        authenticator = LocalAuthenticator(mauth_auth=mock.Mock(),
                                           logger=mock.Mock(),
                                           mauth_api_version='v2',
                                           mauth_base_url='https://mauth-sandbox.imedidata.net')
        self.assertEqual('LOCAL', authenticator.authenticator_type)

    def test_does_not_authenticate_a_false_message(self):
        """Given an authentic message, we authenticate"""
        mws_time = int(time.time())
        headers = self.generate_headers("GET",
                                        "/mauth/v1/mauth.json",
                                        "",
                                        mws_time)
        request = mock.Mock(headers=headers,
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.mauth.authenticators.SecurityTokenCacher") as tok:
            cacher = tok.return_value
            cacher.get.return_value = dict(app_name="Apple",
                                           app_uuid=self.app_uuid,
                                           security_token=dict(public_key_str=load_key('pub')),
                                           created_at="2016-11-20 12:08:46 UTC")
            authenticator = LocalAuthenticator(mauth_auth=mock.Mock(),
                                               logger=mock.Mock(),
                                               mauth_api_version='v2',
                                               mauth_base_url='https://mauth-sandbox.imedidata.net')
            with self.assertRaises(InauthenticError) as exc:
                result = authenticator.signature_valid(request)
            self.assertEqual("Signature verification failed for Mock", str(exc.exception))

    def test_flushes_an_invalid_token(self):
        """Given an authentic message, we authenticate"""
        mws_time = int(time.time())
        headers = self.generate_headers("GET",
                                        "/mauth/v1/mauth.json",
                                        "",
                                        mws_time)
        request = mock.Mock(headers=headers,
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.mauth.authenticators.SecurityTokenCacher") as tok:
            cacher = tok.return_value
            cacher.get.return_value = dict(app_name="Apple",
                                           app_uuid=self.app_uuid,
                                           security_token=dict(public_key_str="pineapple"),
                                           created_at="2016-11-20 12:08:46 UTC")
            flush = mock.Mock()
            cacher.flush = flush
            authenticator = LocalAuthenticator(mauth_auth=mock.Mock(),
                                               logger=mock.Mock(),
                                               mauth_api_version='v2',
                                               mauth_base_url='https://mauth-sandbox.imedidata.net')
            with self.assertRaises(InauthenticError) as exc:
                result = authenticator.signature_valid(request)
            # bad key gets flushed from the cache
            flush.assert_called_once_with(self.app_uuid)
            # message is what we expect
            # We have a problem here, in python3 the '..BEGIN PUBLIC KEY..' is escaped as a b
            assertRegex(self, str(exc.exception),
                        r'Public key decryption of signature failed.*-----BEGIN RSA PUBLIC KEY-----.*found')

    @patch.object(LocalAuthenticator, "authenticate")
    def test_is_authentic_all_ok(self, authenticate):
        """We get a True back if all tests pass"""
        authenticate.return_value = True
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertTrue(authentic)
        self.assertEqual(200, status)

    @patch.object(LocalAuthenticator, "authenticate")
    def test_is_authentic_fails(self, authenticate):
        """We get a False back if one or more tests fail"""
        authenticate.return_value = False
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)

    @patch.object(LocalAuthenticator, "signature_valid")
    @patch.object(LocalAuthenticator, "authentication_present")
    @patch.object(LocalAuthenticator, "time_valid")
    @patch.object(LocalAuthenticator, "token_valid")
    def test_is_authentic_some_token_invalid(self, token_valid, time_valid, authentication_present, signature_valid):
        """LocalAuthenticator: We get a False back if token invalid"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        token_valid.side_effect = InauthenticError()
        time_valid.return_value = True
        authentication_present.return_value = True
        signature_valid.return_value = True
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)

    @patch.object(LocalAuthenticator, "signature_valid")
    @patch.object(LocalAuthenticator, "authentication_present")
    @patch.object(LocalAuthenticator, "time_valid")
    @patch.object(LocalAuthenticator, "token_valid")
    def test_is_authentic_some_time_invalid(self, token_valid, time_valid, authentication_present, signature_valid):
        """LocalAuthenticator: We get a False back if time invalid"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        token_valid.return_value = True
        time_valid.side_effect = InauthenticError()
        authentication_present.return_value = True
        signature_valid.return_value = True
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)

    @patch.object(LocalAuthenticator, "signature_valid")
    @patch.object(LocalAuthenticator, "authentication_present")
    @patch.object(LocalAuthenticator, "time_valid")
    @patch.object(LocalAuthenticator, "token_valid")
    def test_is_authentic_some_authentication_missing(self, token_valid, time_valid, authentication_present,
                                                      signature_valid):
        """LocalAuthenticator: We get a False back if mauth missing"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")

        token_valid.return_value = True
        time_valid.return_value = True
        authentication_present.side_effect = InauthenticError()
        signature_valid.return_value = True
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)

    @patch.object(LocalAuthenticator, "signature_valid")
    @patch.object(LocalAuthenticator, "authentication_present")
    @patch.object(LocalAuthenticator, "time_valid")
    @patch.object(LocalAuthenticator, "token_valid")
    def test_is_authentic_some_signature_invalid(self, token_valid, time_valid, authentication_present,
                                                 signature_valid):
        """LocalAuthenticator: We get a False back if token invalid"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        token_valid.return_value = True
        time_valid.return_value = True
        authentication_present.return_value = True
        signature_valid.side_effect = InauthenticError()
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)

    @patch.object(LocalAuthenticator, "authenticate")
    def test_authenticate_error_conditions_inauthentic(self, authenticate):
        """ We get a False back if we raise a InauthenticError """
        authenticate.side_effect = InauthenticError("")
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)
        self.assertEqual(401, status)
        self.assertEqual("", message)

    @patch.object(LocalAuthenticator, "authenticate")
    def test_authenticate_error_conditions_unable(self, authenticate):
        """LocalAuthenticator: We get a False back if we raise a UnableToAuthenticateError """
        authenticate.side_effect = UnableToAuthenticateError("")
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        authentic, status, message = self.authenticator.is_authentic(request)
        self.assertFalse(authentic)
        self.assertEqual(500, status)
        self.assertEqual("", message)

    @patch.object(LocalAuthenticator, "signature_valid")
    @patch.object(LocalAuthenticator, "authentication_present")
    @patch.object(LocalAuthenticator, "time_valid")
    @patch.object(LocalAuthenticator, "token_valid")
    def test_authenticate_is_ok(self, token_valid, time_valid, authentication_present, signature_valid):
        """LocalAuthenticator:  We get a True back if all tests pass"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        token_valid.return_value = True
        time_valid.return_value = True
        authentication_present.return_value = True
        signature_valid.return_value = True
        authentic = self.authenticator.authenticate(request)
        self.assertTrue(authentic)

    @patch.object(LocalAuthenticator, "signature_valid")
    @patch.object(LocalAuthenticator, "authentication_present")
    @patch.object(LocalAuthenticator, "time_valid")
    @patch.object(LocalAuthenticator, "token_valid")
    def test_authenticate_fails(self, token_valid, time_valid, authentication_present, signature_valid):
        """LocalAuthenticator:  We get a False back if any tests fail"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        token_valid.return_value = True
        time_valid.return_value = True
        authentication_present.return_value = True
        signature_valid.return_value = False
        authentic = self.authenticator.authenticate(request)
        self.assertFalse(authentic)


class TestMWSAttr(TestCase):
    def setUp(self):
        self.mws_time = "1479392498"
        self.app_uuid = 'b0603e5c-c344-488e-83ba-9290ea8dc17d'

    def test_expected_outcome(self):
        """All present, attributes ok"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        expected = ("MWS", self.app_uuid, "somethingelse", self.mws_time)
        self.assertEqual(expected, mws_attr(request))

    def test_unexpected_outcome(self):
        """All present, attributes ok"""
        request = mock.Mock(headers={},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        expected = ("", "", "", "")
        self.assertEqual(expected, mws_attr(request))
