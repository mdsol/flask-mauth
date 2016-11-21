# -*- coding: utf-8 -*-
from time import sleep

__author__ = 'glow'

from unittest import TestCase
import datetime
import os
from mock import mock

from flask_mauth.exceptions import InauthenticError, UnableToAuthenticateError
from flask_mauth.security_token_cacher import SecurityTokenCacher


def load_key(keytype='pub'):
    """
    Load the sample keys
    :param keytype: type of key to load
    :return: key content
    :rtype: str
    """
    assert keytype in ('pub', 'priv')
    content = ""
    with open(os.path.join(os.path.dirname(__file__),
                             'yourname_mauth.%s.key' % keytype), 'r') as key:
        content = key.read()
    return content


class TestSecurityTokenCacher(TestCase):
    def setUp(self):
        self.app_uuid = 'b0603e5c-c344-488e-83ba-9290ea8dc17d'
        self.public_key = load_key()

    def test_request_for_known_app_uses_cache(self):
        """A previously downloaded token is returned """
        ticket = dict(app_name="Some App",
                      app_uuid=self.app_uuid,
                      public_key_str=self.public_key,
                      created_at=datetime.datetime.now())
        cacher = SecurityTokenCacher()
        with mock.patch("flask_mauth.security_token_cacher.requests.get") as req:
            req.return_value = mock.Mock(status_code=200)
            req.json.return_value = ticket
            # this will fetch
            token = cacher.get(self.app_uuid)
            # this will retrieve
            token = cacher.get(self.app_uuid)
        self.assertEqual(1, req.call_count)

    def test_request_for_expired_app_fetches(self):
        """ An expired cache token will be refetched """
        ticket = dict(app_name="Some App",
                      app_uuid=self.app_uuid,
                      public_key_str=self.public_key,
                      created_at=datetime.datetime.now())
        cacher = SecurityTokenCacher(cache_life=0.001)
        with mock.patch("flask_mauth.security_token_cacher.requests.get") as req:
            req.return_value = mock.Mock(status_code=200)
            req.json.return_value = ticket
            # this will fetch
            token = cacher.get(self.app_uuid)
            sleep(0.1)
            # this will fetch
            token = cacher.get(self.app_uuid)
        self.assertEqual(2, req.call_count)

    def test_request_for_unknown_app_raises(self):
        """ An unknown token returns an InauthenticError """
        ticket = dict(app_name="Some App",
                      app_uuid=self.app_uuid,
                      public_key_str=self.public_key,
                      created_at=datetime.datetime.now())
        cacher = SecurityTokenCacher()
        with mock.patch("flask_mauth.security_token_cacher.requests.get") as req:
            req.return_value = mock.Mock(status_code=404)
            # this will fetch
            with self.assertRaises(InauthenticError) as exc:
                token = cacher.get(self.app_uuid)
            self.assertEqual(str(exc.exception),
                             "mAuth service responded with 404 looking up public "
                             "key for {app_uuid}".format(app_uuid=self.app_uuid))
        self.assertEqual(1, req.call_count)

    def test_mauth_error_raises(self):
        """ A MAuth Service error raises an UnableToAuthenticateError """
        cacher = SecurityTokenCacher()
        with mock.patch("flask_mauth.security_token_cacher.requests.get") as req:
            req.return_value = mock.Mock(status_code=500, content="GULP")
            # this will fetch
            with self.assertRaises(UnableToAuthenticateError) as exc:
                token = cacher.get(self.app_uuid)
            self.assertEqual(str(exc.exception),
                             "The mAuth service responded "
                             "with 500: GULP")
        self.assertEqual(1, req.call_count)

    def test_incorrect_app_uuid_raises(self):
        """ A invalid UUID raises an UnableToAuthenticateError """
        cacher = SecurityTokenCacher()
        # pass in attempts to escape using paths
        for garbage in ('%s/../../' % self.app_uuid, '../../%s' % self.app_uuid,
                        'horse', '1234'):
            with self.assertRaises(UnableToAuthenticateError) as exc:
                token = cacher.get(garbage)
            self.assertEqual(str(exc.exception),
                             "APP UUID format is not conformant")
