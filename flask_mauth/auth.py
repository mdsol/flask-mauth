# -*- coding: utf-8 -*-
import logging
from functools import wraps

from flask import Response, current_app, request
from requests_mauth import MAuth

from flask_mauth.mauth import LocalAuthenticator, RemoteAuthenticator

logger = logging.getLogger("flask_mauth")


class MAuthAuthenticator(object):
    state_key = 'flask_mauth.client'

    def __init__(self, app=None):
        # backwards compatibility support
        self._app = app
        self._authenticator = None
        if app:
            self.init_app(app)

    @property
    def app_uuid(self):
        """
        Get the MAuth APP UUID
        :return: MAuth APP UUID
        :rtype: str
        """
        return self._app.config.get('MAUTH_APP_UUID')

    @property
    def mauth_key(self):
        """
        Get the MAuth Key Text
        :return: MAuth Key Text
        :rtype: str
        """
        return self._app.config.get('MAUTH_KEY_DATA')

    @property
    def mauth_base_url(self):
        """
        Get the MAuth Base URL
        :return: MAuth Base URL
        :rtype: str
        """
        return self._app.config.get('MAUTH_BASE_URL')

    @property
    def mauth_version(self):
        """
        Get the MAuth Version (defaults to v2)
        :return: MAuth Version
        :rtype: str
        """
        return self._app.config.get('MAUTH_VERSION', 'v2')

    @property
    def mauth_mode(self):
        """
        Get the MAuth Authentication Mode
        :return: Defined MAuth Authentication Mode (defaults to local)
        :rtype: str
        """
        return self._app.config.get('MAUTH_MODE', 'local')

    def _create_authenticator(self):
        # Validate the client settings (MAUTH_APP_UUID, MAUTH_KEY_DATA)
        if None in (self.app_uuid, self.mauth_key) or '' in (self.app_uuid, self.mauth_key):
            raise TypeError("MAuthAuthenticator requires both a MAUTH_APP_UUID and MAUTH_KEY_DATA to be set")
        # Validate the mauth settings (MAUTH_BASE_URL, MAUTH_VERSION)
        if None in (self.mauth_base_url, self.mauth_version) or '' in  (self.mauth_base_url, self.mauth_version):
            raise TypeError("MAuthAuthenticator requires a MAUTH_BASE_URL and MAUTH_VERSION")
        # Validate MAUTH_MODE
        if self.mauth_mode not in ("local", "remote"):
            raise TypeError("MAuthAuthenticator MAUTH_MODE must be one of local or remote")
        # create the mauth_client
        mauth_client = MAuth(self.app_uuid, self.mauth_key)
        if self.mauth_mode == 'local':
            authenticator = LocalAuthenticator(mauth_auth=mauth_client,
                                               logger=logger,
                                               mauth_base_url=self.mauth_base_url,
                                               mauth_api_version=self.mauth_version)
        else:
            authenticator = RemoteAuthenticator(mauth_auth=mauth_client,
                                                logger=logger,
                                                mauth_base_url=self.mauth_base_url,
                                                mauth_api_version=self.mauth_version)
        return authenticator

    def authenticate(self, request):
        return self._authenticator.is_authentic(request)

    def init_app(self, app):
        """Init app with Flask instance.

        You can also pass the instance of Flask later::
            mauth = MAuthAuthenticator()
            mauth.init_app(app)
        """
        self._app = app
        app.authenticator = self
        app.extensions = getattr(app, 'extensions', {})
        app.extensions[self.state_key] = self
        # initialise the authenticator
        self._authenticator = self._create_authenticator()


def requires_authentication(f):
    """
    A Decorator for routes requiring mauth authentication
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        authenticator = current_app.authenticator
        if not authenticator.authenticate(request):
            # TODO: do we return the underlying error?  Currently going into the log
            return Response('Precondition failed', 412)
        return f(*args, **kwargs)
    return wrapper
