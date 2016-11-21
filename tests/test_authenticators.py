# -*- coding: utf-8 -*-

__author__ = 'glow'

from unittest import TestCase
from mock import mock
import datetime
import time
import six

from flask_mauth.authenticators import MAuthAuthenticator, RemoteAuthenticator
from flask_mauth.exceptions import InauthenticError, UnableToAuthenticateError


class TestAuthenticator(TestCase):
    def setUp(self):
        self.authenticator = MAuthAuthenticator(mauth_auth=mock.Mock(),
                                                logger=mock.Mock(),
                                                mauth_api_version='v2',
                                                mauth_base_url='https://mauth-sandbox.imedidata.net')

    def test_authentication_present_happy_path(self):
        """With the header present, we are ok"""
        request = mock.Mock(headers={'X_MWS_AUTHENTICATION': 'MWS 1234'})
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
        request = mock.Mock(headers={'X_MWS_AUTHENTICATION': ''})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.authentication_present(request)
        self.assertEqual(str(exc.exception),
                         "Authentication Failed. No mAuth signature present; X-MWS-Authentication header is blank."
                         )

    def test_time_valid_happy_path(self):
        """With an ok time, we are ok"""
        now = int(time.time())
        request = mock.Mock(headers={'X_MWS_TIME': '%s' % now})
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
        request = mock.Mock(headers={'X_MWS_TIME': 'apple'})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.time_valid(request=request)
        self.assertEqual(str(exc.exception),
                         "Time verification failed for Mock. X-MWS-Time Header format incorrect.",
                         )

    def test_time_valid_empty_header(self):
        """With an empty header, we get an exception"""
        request = mock.Mock(headers={'X_MWS_TIME': ''})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.time_valid(request=request)
        self.assertEqual(str(exc.exception),
                         "Time verification failed for Mock. No x-mws-time present.",
                         )

    def test_time_valid_expired_header(self):
        """With an empty header, we get an exception"""
        now = int(time.time()) - (MAuthAuthenticator.ALLOWED_DRIFT_SECONDS * 100 + 1)
        request = mock.Mock(headers={'X_MWS_TIME': str(now)})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.time_valid(request=request)
        six.assertRegex(self,
                        str(exc.exception),
                        r"Time verification failed for Mock. %s "
                        "not within %ss of [0-9\-]{10} [0-9\:]{7}" % (datetime.datetime.fromtimestamp(now),
                                                                      MAuthAuthenticator.ALLOWED_DRIFT_SECONDS),
                        )

    def test_token_valid_happy_path(self):
        """With an expected header, all good"""
        request = mock.Mock(headers={'X_MWS_AUTHENTICATION': 'MWS some-uuid:some hash'})
        self.assertTrue(self.authenticator.token_valid(request))

    def test_token_valid_invalid_token(self):
        """Invalid token leads to exception"""
        request = mock.Mock(headers={'X_MWS_AUTHENTICATION': 'RWS some-uuid:some hash'})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.token_valid(request)
        self.assertEqual(str(exc.exception),
                         "Token verification failed for Mock. Expected MWS; token was RWS"
                         )

    def test_token_valid_bad_format(self):
        """Badly formatted signature leads to exception"""
        request = mock.Mock(headers={'X_MWS_AUTHENTICATION': 'MWS'})
        with self.assertRaises(InauthenticError) as exc:
            self.authenticator.token_valid(request)
        self.assertEqual(str(exc.exception),
                         "Token verification failed for Mock. Misformatted Signature.")


class TestRemoteAuthenticator(TestAuthenticator):
    """
    Remotely authenticate a request
    """

    def setUp(self):
        self.authenticator = RemoteAuthenticator(mauth_auth=mock.Mock(),
                                                 logger=mock.Mock(),
                                                 mauth_api_version='v2',
                                                 mauth_base_url='https://mauth-sandbox.imedidata.net')
        self.mws_time = "1479392498"
        self.app_uuid = 'b0603e5c-c344-488e-83ba-9290ea8dc17d'

    def test_signature_valid(self):
        """ With a valid request we get a 200 response """
        request = mock.Mock(headers=dict(X_MWS_TIME=self.mws_time,
                                         X_MWS_AUTHENTICATION="MWS %s:somethingelse" % self.app_uuid),
                            path="/mauth/v2/authentication.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.authenticators.requests") as req:
            req.post.return_value = mock.Mock(status_code=200)
            result = self.authenticator.signature_valid(request=request)
        self.assertTrue(result)

    def test_signature_invalid_412(self):
        """ With a valid request we get a 412 response """
        request = mock.Mock(headers=dict(X_MWS_TIME=self.mws_time,
                                         X_MWS_AUTHENTICATION="MWS %s:somethingelse" % self.app_uuid),
                            path="/mauth/v2/authentication.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.authenticators.requests") as req:
            req.post.return_value = mock.Mock(status_code=412, content="Blurgle")
            with self.assertRaises(InauthenticError) as exc:
                result = self.authenticator.signature_valid(request=request)
            self.assertEqual(str(exc.exception),
                             "The mAuth service responded with 412: Blurgle")

    def test_signature_invalid_404(self):
        """ With a valid request we get a 412 response """
        request = mock.Mock(headers=dict(X_MWS_TIME=self.mws_time,
                                         X_MWS_AUTHENTICATION="MWS %s:somethingelse" % self.app_uuid),
                            path="/mauth/v2/authentication.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.authenticators.requests") as req:
            req.post.return_value = mock.Mock(status_code=404, content="Blargle")
            with self.assertRaises(InauthenticError) as exc:
                result = self.authenticator.signature_valid(request=request)
            self.assertEqual(str(exc.exception),
                             "The mAuth service responded with 404: Blargle")

    def test_upstream_error(self):
        """ With a mauth server problem """
        request = mock.Mock(headers=dict(X_MWS_TIME=self.mws_time,
                                         X_MWS_AUTHENTICATION="MWS %s:somethingelse" % self.app_uuid),
                            path="/mauth/v2/authentication.json?open=1",
                            method="GET",
                            data="")
        with mock.patch("flask_mauth.authenticators.requests") as req:
            req.post.return_value = mock.Mock(status_code=500, content="Urgle")
            with self.assertRaises(UnableToAuthenticateError) as exc:
                result = self.authenticator.signature_valid(request=request)
            self.assertEqual(str(exc.exception),
                             "The mAuth service responded with 500: Urgle")


class TestLocalAuthenticator(TestAuthenticator):
    pass
