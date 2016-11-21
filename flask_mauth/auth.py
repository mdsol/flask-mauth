# -*- coding: utf-8 -*-

from sre_compile import isstring

from requests_mauth import MAuth


class MAuthMiddleware(object):

    def __init__(self, app=None,
                 app_uuid=None,
                 private_key_text=None,
                 mauth_base_url=None,
                 mauth_api_version=None):
        # backwards compatibility support
        if isstring(app):
            from warnings import warn
            warn(DeprecationWarning('MAuth constructor expects application '
                                    'as first argument now.  If you want to '
                                    'provide a hardcoded fs_store_path you '
                                    'have to use a keyword argument.  It is '
                                    'recommended though to use the config '
                                    'key.'), stacklevel=2)
            app = None
        self.app = app
        if None in (app_uuid, private_key_text):
            raise Exception("Need the MAuth Credentials")
        # define the authentication object
        auth = MAuth(app_uuid=app_uuid, private_key_data=private_key_text)
        self.mauth_base_url = mauth_base_url
        self.mauth_api_version = mauth_api_version

    def __call__(self, environ, start_response):
        pass

    def _authenticated(self, header):
        if not header:
            return False

    def init_app(self, app, ):
        """This callback can be used to initialize an application for the
        use with this openid controller.
        .. versionadded:: 1.0
        """
        app.config.setdefault('OPENID_FS_STORE_PATH', None)
