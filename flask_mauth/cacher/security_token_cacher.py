# -*- coding: utf-8 -*-

__author__ = 'glow'

import cachetools
import requests
from six.moves.urllib.parse import urljoin

from flask_mauth.exceptions import InauthenticError, UnableToAuthenticateError
from flask_mauth.settings import uuid_pattern


class SecurityTokenCacher(object):
    """
    Cache the retrieved tokens from the remote site
    """

    def __init__(self, mauth_auth=None, mauth_base_url=None, mauth_api_version=None, cache_life=60):
        # type: (requests_mauth.MAuth, str, str) -> None
        self.auth = mauth_auth
        self._cache = cachetools.TTLCache(100,
                                          cache_life)
        self.mauth_base_url = mauth_base_url
        self.mauth_api_version = mauth_api_version

    def flush(self, app_uuid):
        """
        Expire a token
        :param app_uuid: APP UUID to expire
        """
        if app_uuid in self._cache:
            del self._cache[app_uuid]

    def get(self, app_uuid):
        if app_uuid not in self._cache:
            # pull the remote credentials, if this fails it raises an InauthenticError
            self._remote_get(app_uuid)
        return self._cache.get(app_uuid)

    def _remote_get(self, app_uuid):
        # type: (str) -> None
        if not uuid_pattern.match(app_uuid):
            raise UnableToAuthenticateError("APP UUID format is not conformant")
        url = urljoin(self.mauth_base_url, "/mauth/{mauth_api_version}/security_tokens" \
                                           "/{app_uuid}.json".format(mauth_api_version=self.mauth_api_version,
                                                                     app_uuid=app_uuid))
        response = requests.get(url, auth=self.auth)
        if response.status_code == 404:
            raise InauthenticError("mAuth service responded with 404 looking up public "
                                   "key for {app_uuid}".format(app_uuid=app_uuid))
        elif response.status_code == 200:
            self._cache[app_uuid] = response.json()
        else:
            raise UnableToAuthenticateError("The mAuth service responded "
                                            "with {status}: {body}".format(status=response.status_code,
                                                                           body=response.content), response)
