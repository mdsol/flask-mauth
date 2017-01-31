# -*- coding: utf-8 -*-

import abc
import datetime
import json
from base64 import b64encode

import requests
from six.moves.urllib.parse import urljoin

from flask_mauth import settings
from flask_mauth.cacher import SecurityTokenCacher
from flask_mauth.exceptions import InauthenticError, UnableToAuthenticateError
from flask_mauth.mauth.signature import Signature
from flask_mauth.rsa_public_decrypt import RSAPublicKey


def mws_attr(request):
    """
    Extract the MWS Headers from a Request

    :param request: Request object
    :type request: werkzeug.wrappers.BaseRequest
    :return: Token, APP_UUID,  Time since Epoch
    :rtype: str, str, str
    """
    token, app_uuid, signature, mws_time = "", "", "", ""
    if settings.x_mws_authentication in request.headers:
        token, app_uuid, signature = settings.signature_info.match(
            request.headers.get(settings.x_mws_authentication)).groups()
    if settings.x_mws_time in request.headers:
        mws_time = request.headers.get(settings.x_mws_time)
    return token, app_uuid, signature, mws_time


class AbstractMAuthAuthenticator(object):
    __metaclass__ = abc.ABCMeta
    """
    Abstract Base Class for the Local and Remote Authentication classes
    """

    ALLOWED_DRIFT_SECONDS = 300

    def __init__(self, mauth_auth, logger, mauth_base_url, mauth_api_version):
        """
        :param mauth_auth: MAuth object
        :type mauth_auth: requests_mauth.client.MAuth
        :param logger: Logger for messages (TBD)
        :param mauth_base_url: MAuth Base URL
        :type mauth_base_url: str
        :param mauth_api_version: MAuth API version
        :type mauth_api_version: str
        """
        self._mauth_auth = mauth_auth
        self._logger = logger
        self._mauth_base_url = mauth_base_url
        self._mauth_api_version = mauth_api_version

    def authenticate(self, request):
        """
        Authenticate the request, by checking all the sub-category of issues

        :param request: Request object
        :type request: werkzeug.wrappers.BaseRequest
        """
        if self.authentication_present(request) and self.time_valid(request) and \
                self.token_valid(request) and self.signature_valid(request):
            return True
        return False

    def is_authentic(self, request):
        """
        Overall Wrapper for mauth

        :param request: Request object
        :type request: werkzeug.wrappers.BaseRequest
        :return: Is the request authentic?, Status Code, Message
        :rtype: (bool, int, str)
        """
        self.log_authentication_request(request)
        authentic = False
        try:
            authentic = self.authenticate(request)
        except InauthenticError as exc:
            self.log_authentication_error(request, str(exc))
            return False, 401, str(exc)
        except UnableToAuthenticateError as exc:
            self.log_authentication_error(request, str(exc))
            return False, 500, str(exc)
        return authentic, 200 if authentic else 401, ''

    def authentication_present(self, request):
        """
        Is the mauth header present (assuming request has a headers attribute) that
        can be treated like a dict

        :param request: Request object
        :type request: werkzeug.wrappers.BaseRequest
        :rtype: bool
        :return: success
        """
        if request.headers.get(settings.x_mws_authentication, '') == '':
            raise InauthenticError(
                "Authentication Failed. No mAuth signature present; X-MWS-Authentication header is blank.")
        return True

    def time_valid(self, request):
        """
        Is the time of the request within the allowed drift?

        :param request: Request like object
        :type request: werkzeug.wrappers.BaseRequest
        :rtype: bool
        :return: success
        """
        if request.headers.get(settings.x_mws_time, '') == '':
            raise InauthenticError(
                "Time verification failed for {}. No x-mws-time present.".format(request.__class__.__name__))
        if not str(request.headers.get(settings.x_mws_time, '')).isdigit():
            raise InauthenticError(
                "Time verification failed for {}. X-MWS-Time Header format incorrect.".format(
                    request.__class__.__name__))
        now = datetime.datetime.now()
        # this needs a float
        signature_time = datetime.datetime.fromtimestamp(float(request.headers.get(settings.x_mws_time)))
        if now > signature_time + datetime.timedelta(seconds=self.ALLOWED_DRIFT_SECONDS):
            raise InauthenticError("Time verification failed for {}. {} "
                                   "not within {}s of {}".format(request.__class__.__name__,
                                                                 signature_time,
                                                                 self.ALLOWED_DRIFT_SECONDS,
                                                                 now.strftime("%Y-%m-%d %H:%M:%S")))
        return True

    def token_valid(self, request):
        """
        Is the message signed correctly?

        :param request: Request object
        :type request: werkzeug.wrappers.BaseRequest
        :rtype: bool
        :return: success
        """
        if not settings.signature_info.match(request.headers.get(settings.x_mws_authentication)):
            raise InauthenticError("Token verification failed for {}. Misformatted "
                                   "Signature.".format(request.__class__.__name__))
        token, app_uuid, signature, mws_time = mws_attr(request)
        if not token == settings.mws_token:
            raise InauthenticError("Token verification failed for {}. "
                                   "Expected {}; token was {}".format(request.__class__.__name__,
                                                                      settings.mws_token, token))
        return True

    @abc.abstractmethod
    def signature_valid(self, request):  # pragma: no cover
        """
        This should be implemented by the child classes

        :param request: the Request Object
        :type request: werkzeug.wrappers.BaseRequest
        """
        return

    def log_mauth_service_response_error(self, request, response):
        """
        Upstream MAuth Service error

        :param request: Original Request Object
        :type request: werkzeug.wrappers.BaseRequest
        :param response: Returned Response Object
        :type response: werkzeug.wrappers.BaseResponse
        """
        token, app_uuid, signature, mws_time = mws_attr(request)
        message = "MAuth Service: App UUID: {app_uuid}; URL: {url}; " \
                  "MAuth service responded with {status}: {body}".format(
            app_uuid=app_uuid,
            url=request.path,
            status=response.status_code,
            body=response.data)
        self._logger.error(message)
        raise UnableToAuthenticateError(message, response)

    def log_authentication_error(self, request, message=""):
        """
        Log an error with an authenticated request

        :param request: request object
        :type request: werkzeug.wrappers.BaseRequest
        :param message: any message that is exposed
        :type message: str
        """
        token, app_uuid, signature, mws_time = mws_attr(request)
        if app_uuid == "":
            app_uuid = "MISSING"
        self._logger.error("MAuth Authentication Error: App UUID: {}; URL: {}; Error: {}".format(app_uuid,
                                                                                                 request.path,
                                                                                                 message))

    def log_authentication_request(self, request):
        """
        Log an authenticated request

        :param request: request object
        :type request: werkzeug.wrappers.BaseRequest
        """
        token, app_uuid, signature, mws_time = mws_attr(request)
        if app_uuid == "":
            app_uuid = "MISSING"
        self._logger.info("MAuth Request: App UUID: {}; URL: {}".format(app_uuid,
                                                                        request.path))

    @property
    def authenticator_type(self):
        """
        Return the Authenticator Type
        """
        return self.AUTHENTICATION_TYPE


class RemoteAuthenticator(AbstractMAuthAuthenticator):
    """
    Remote Authentication object, passes through the authentication to the upstream MAuth Server
    """
    AUTHENTICATION_TYPE = "REMOTE"

    def __init__(self, mauth_auth, logger, mauth_base_url, mauth_api_version):
        """
        :param mauth_auth: Configured MAuth Client
        :type mauth_auth: requests_mauth.client.MAuth
        :param logger: configured Flask Logger
        :param str mauth_base_url: The Base URL for the mauth server
        :param str mauth_api_version: API Version for the mauth server
        """
        super(RemoteAuthenticator, self).__init__(mauth_auth=mauth_auth, logger=logger,
                                                  mauth_base_url=mauth_base_url,
                                                  mauth_api_version=mauth_api_version)

    def signature_valid(self, request):
        """
        Is the signature valid?

        :param request: Request instance
        :type request: werkzeug.wrappers.BaseRequest
        """
        token, app_uuid, signature, mws_time = mws_attr(request)
        url = urljoin(self._mauth_base_url, "/mauth/{mauth_api_version}/" \
                                            "authentication_tickets.json".format(
            mauth_api_version=self._mauth_api_version))
        authentication_ticket = dict(verb=request.method,
                                     app_uuid=app_uuid,
                                     client_signature=signature,
                                     request_url=request.path,
                                     request_time=mws_time,
                                     b64encoded_body=b64encode(request.data.encode('utf-8')).decode('utf-8')
                                     )
        response = requests.post(url,
                                 data=json.dumps(dict(authentication_ticket=authentication_ticket)),
                                 auth=self._mauth_auth)
        if response.status_code in (412, 404):
            # the mAuth service responds with 412 when the given request is not authentically signed.
            # older versions of the mAuth service respond with 404 when the given app_uuid
            # does not exist, which is also considered to not be authentically signed. newer
            # versions of the service respond 412 in all cases, so the 404 check may be removed
            # when the old version of the mAuth service is out of service.
            raise InauthenticError("The mAuth service responded with {status}: {body}".format(
                status=response.status_code,
                body=response.content))
        elif 200 <= response.status_code <= 299:
            return True
        else:
            # e.g. 500 error
            # NOTE: this raises the underlying UnableToAuthenticateError
            self.log_mauth_service_response_error(request=request,
                                                  response=response)


class LocalAuthenticator(AbstractMAuthAuthenticator):
    """
    Local Authentication object, authenticates the request locally, retrieving the necessary credentials from the
    upstream MAuth Server
    """
    AUTHENTICATION_TYPE = "LOCAL"

    def __init__(self, mauth_auth, logger, mauth_base_url, mauth_api_version):
        """
        :param mauth_auth: Configured MAuth Client
        :type mauth_auth: requests_mauth.client.MAuth
        :param logger: configured Flask Logger
        :param str mauth_base_url: The Base URL for the mauth server
        :param str mauth_api_version: API Version for the mauth server
        """
        super(LocalAuthenticator, self).__init__(mauth_auth=mauth_auth, logger=logger,
                                                 mauth_base_url=mauth_base_url,
                                                 mauth_api_version=mauth_api_version)
        self.secure_token_cacher = SecurityTokenCacher(mauth_auth=mauth_auth,
                                                       mauth_api_version=mauth_api_version,
                                                       mauth_base_url=mauth_base_url)

    def signature_valid(self, request):
        """
        Is the signature valid?

        :param request: request object
        :type request: werkzeug.wrappers.BaseRequest
        """

        token, app_uuid, signature, mws_time = mws_attr(request)

        expected = Signature.from_request(request=request)
        try:
            token = self.secure_token_cacher.get(app_uuid=app_uuid)
            rsakey = RSAPublicKey.load_pkcs1(token.get('security_token').get('public_key_str'))
            padded = rsakey.public_decrypt(signature)
            signature_hash = rsakey.unpad_message(padded)
        except ValueError as exc:
            self.secure_token_cacher.flush(app_uuid)
            # importKey raises
            raise InauthenticError("Public key decryption of signature "
                                   "failed!: {}".format(exc))
        if not expected.matches(signature_hash):
            raise InauthenticError("Signature verification failed for {}".format(request.__class__.__name__))
        return True
