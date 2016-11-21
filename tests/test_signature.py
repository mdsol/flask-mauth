# -*- coding: utf-8 -*-

__author__ = 'glow'

from unittest import TestCase
import mock
from flask_mauth.signature import Signature


class TestSignature(TestCase):
    def setUp(self):
        self.mws_time = "1479392498"
        self.app_uuid = 'b0603e5c-c344-488e-83ba-9290ea8dc17d'

    def test_create_from_request(self):
        """Create a Signature from a request"""
        request = mock.Mock(headers=dict(X_MWS_TIME=self.mws_time,
                                         X_MWS_AUTHENTICATION="MWS %s:somethingelse" % self.app_uuid),
                            path="/mauth/v2/authentication.json?open=1",
                            method="GET",
                            data="")
        signature = Signature.from_request(request)
        self.assertEqual("GET", signature.verb)
        self.assertEqual(self.app_uuid, signature.app_uuid)
        self.assertEqual("/mauth/v2/authentication.json", signature.url_path)
        self.assertEqual(self.mws_time, signature.seconds_since_epoch)

    def test_equality_of_req(self):
        """Create a duplicate Signature from a request and then check they are equal"""
        request = mock.Mock(headers=dict(X_MWS_TIME=self.mws_time,
                                         X_MWS_AUTHENTICATION="MWS %s:somethingelse" % self.app_uuid),
                            path="/mauth/v2/authentication.json?open=1",
                            method="GET",
                            data="")
        signature = Signature.from_request(request)
        signature_1 = Signature.from_request(request)
        self.assertEqual(signature, signature_1)

    def test_creates_from_string(self):
        """Create a Signature from a string"""
        # expected string
        sig_string = "GET" + "\n" + \
                   "/mauth/v2/authentication.json" + "\n" + \
                     "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        signature = Signature.from_signature(sig_string)
        self.assertEqual("GET", signature.verb)
        self.assertEqual(self.app_uuid, signature.app_uuid)
        self.assertEqual("/mauth/v2/authentication.json", signature.url_path)
        self.assertEqual(self.mws_time, signature.seconds_since_epoch)

    def test_equality_of_str(self):
        """Create a duplicate Signature from a string and then check they are equal"""
        sig_string = "GET" + "\n" + \
                   "/mauth/v2/authentication.json" + "\n" + \
                   "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        signature = Signature.from_signature(sig_string)
        signature_1 = Signature.from_signature(sig_string)
        self.assertEqual(signature, signature_1)

    def test_equality_of_str_and_req(self):
        """Create a Signature from a string and request and then check they are equal"""
        sig_string = "GET" + "\n" + \
                   "/mauth/v2/authentication.json" + "\n" + \
                   "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        signature = Signature.from_signature(sig_string)
        request = mock.Mock(headers=dict(X_MWS_TIME=self.mws_time,
                                         X_MWS_AUTHENTICATION="MWS %s:somethingelse" % self.app_uuid),
                            path="/mauth/v2/authentication.json?open=1",
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
        request = mock.Mock(headers=dict(X_MWS_TIME=self.mws_time,
                                         X_MWS_AUTHENTICATION="MWS %s:somethingelse" % self.app_uuid),
                            path="/mauth/v2/authentication.json?open=1",
                            method="GET",
                            data="")
        signature_1 = Signature.from_request(request)
        self.assertNotEqual(signature, signature_1)

    def test_inequality_of_str_and_req_ignores_query(self):
        """Create a Signature from a string and request and then check they are equal with different paths w. query"""
        sig_string = "GET" + "\n" + \
                   "/mauth/v2/authentication.json" + "\n" + \
                   "" + "\n" + \
                   self.app_uuid + "\n" + \
                   self.mws_time
        signature = Signature.from_signature(sig_string)
        request = mock.Mock(headers=dict(X_MWS_TIME=self.mws_time,
                                         X_MWS_AUTHENTICATION="MWS %s:somethingelse" % self.app_uuid),
                            path="/mauth/v2/authentication.json?open=1",
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
        request = mock.Mock(headers=dict(X_MWS_TIME=self.mws_time,
                                         X_MWS_AUTHENTICATION="MWS %s:somethingelse" % self.app_uuid),
                            path="/mauth/v2/authentication.json?open=1",
                            method="GET",
                            data="")
        signature_1 = Signature.from_request(request)
        self.assertNotEqual(signature, signature_1)

    #
    # def test_creates_expected_string_without_query(self):
    #     """We create the expected string"""
    #     mws_time = "1479392498"
    #     app_uuid = 'b0603e5c-c344-488e-83ba-9290ea8dc17d'
    #     # expected string
    #     expected = "GET" + "\n" + \
    #                "/mauth/v2/authentication.json" + "\n" + \
    #                "" + "\n" + \
    #                app_uuid + "\n" + \
    #                mws_time
    #     request = mock.Mock(headers=dict(X_MWS_TIME=mws_time,
    #                                      X_MWS_AUTHENTICATION="MWS %s:somethingelse" % app_uuid),
    #                         path="/mauth/v2/authentication.json",
    #                         method="GET",
    #                         data='')
    #     self.assertEqual(expected, make_signature_string(request))
