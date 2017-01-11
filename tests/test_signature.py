# -*- coding: utf-8 -*-

from unittest import TestCase
import mock
from flask_mauth.mauth.signature import Signature
from flask_mauth import settings
from tests.common import get_hash


class TestSignature(TestCase):
    def setUp(self):
        self.mws_time = "1479392498"
        self.app_uuid = 'b0603e5c-c344-488e-83ba-9290ea8dc17d'

    def test_create_from_request(self):
        """Create a Signature from a request"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        signature = Signature.from_request(request)
        self.assertEqual("GET", signature.verb)
        self.assertEqual(self.app_uuid, signature.app_uuid)
        self.assertEqual("/mauth/v2/mauth.json", signature.url_path)
        self.assertEqual(self.mws_time, signature.seconds_since_epoch)

    def test_equality_of_req(self):
        """Create a duplicate Signature from a request and then check they are equal"""
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        signature = Signature.from_request(request)
        signature_1 = Signature.from_request(request)
        self.assertEqual(signature, signature_1)

    def test_creates_from_string(self):
        """Create a Signature from a string"""
        # expected string
        sig_string = "GET" + "\n" + \
                   "/mauth/v2/mauth.json" + "\n" + \
                     "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        signature = Signature.from_signature(sig_string)
        self.assertEqual("GET", signature.verb)
        self.assertEqual(self.app_uuid, signature.app_uuid)
        self.assertEqual("/mauth/v2/mauth.json", signature.url_path)
        self.assertEqual(self.mws_time, signature.seconds_since_epoch)

    def test_equality_of_str(self):
        """Create a duplicate Signature from a string and then check they are equal"""
        sig_string = "GET" + "\n" + \
                   "/mauth/v2/mauth.json" + "\n" + \
                   "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        signature = Signature.from_signature(sig_string)
        signature_1 = Signature.from_signature(sig_string)
        self.assertEqual(signature, signature_1)

    def test_equality_of_str_and_req(self):
        """Create a Signature from a string and request and then check they are equal"""
        sig_string = "GET" + "\n" + \
                   "/mauth/v2/mauth.json" + "\n" + \
                   "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        signature = Signature.from_signature(sig_string)
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        signature_1 = Signature.from_request(request)
        self.assertEqual(signature, signature_1)

    def test_inequality_of_str_and_req(self):
        """Create a Signature from a string and request and then check they are not equal with different path"""
        sig_string = "GET" + "\n" + \
                   "/mauth/v2/authentication_ticket.json" + "\n" + \
                   "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        signature = Signature.from_signature(sig_string)
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        signature_1 = Signature.from_request(request)
        self.assertNotEqual(signature, signature_1)

    def test_inequality_of_str_and_req_ignores_query(self):
        """Create a Signature from a string and request and then check they are equal with different paths w. query"""
        sig_string = "GET" + "\n" + \
                   "/mauth/v2/mauth.json" + "\n" + \
                   "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        signature = Signature.from_signature(sig_string)
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        signature_1 = Signature.from_request(request)
        self.assertEqual(signature, signature_1)

    def test_equality_of_str_and_req_with_escaping(self):
        """Create a Signature from a string and request and then check they are not equal with different paths"""
        sig_string = "GET" + "\n" + \
                   "/mauth/v2/authentication_ticket.json" + "\n" + \
                   "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        signature = Signature.from_signature(sig_string)
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        signature_1 = Signature.from_request(request)
        self.assertNotEqual(signature, signature_1)
        self.assertFalse(signature == signature_1)

    def test_matches_when_it_should(self):
        """When supplied with a valid hash we match"""
        str_to_sign = "GET" + "\n" + \
                   "/mauth/v2/mauth.json" + "\n" + \
                   "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        hashed = get_hash(str_to_sign)
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        signature_1 = Signature.from_request(request)
        self.assertTrue(signature_1.matches(hashed))

    def test_does_not_match(self):
        """When supplied with an invalid hash we don't match"""
        str_to_sign = "GET" + "\n" + \
                   "/mauth/v1/mauth.json" + "\n" + \
                   "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        hashed = get_hash(str_to_sign)
        request = mock.Mock(headers={settings.x_mws_time: self.mws_time,
                                     settings.x_mws_authentication: "MWS %s:somethingelse" % self.app_uuid},
                            path="/mauth/v2/mauth.json?open=1",
                            method="GET",
                            data="")
        signature_1 = Signature.from_request(request)
        self.assertFalse(signature_1.matches(hashed))


    #
    # def test_creates_expected_string_without_query(self):
    #     """We create the expected string"""
    #     mws_time = "1479392498"
    #     app_uuid = 'b0603e5c-c344-488e-83ba-9290ea8dc17d'
    #     # expected string
    #     request = mock.Mock(headers=dict(X_MWS_TIME=mws_time,
    #                                      X_MWS_AUTHENTICATION="MWS %s:somethingelse" % app_uuid),
    #                         path="/mauth/v2/mauth.json",
    #                         method="GET",
    #                         data='')
    #     self.assertEqual(expected, make_signature_string(request))
