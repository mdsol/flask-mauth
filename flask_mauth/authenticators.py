# -*- coding: utf-8 -*-

import datetime
import json
from base64 import b64decode, b64encode

import werkzeug
from six.moves.urllib.parse import urljoin, urlparse

import requests
from Crypto.PublicKey import RSA

from flask_mauth import settings
from flask_mauth.exceptions import InauthenticError, UnableToAuthenticateError
from flask_mauth.security_token_cacher import SecurityTokenCacher

__author__ = 'glow'

class MAuthAuthenticator(object):
    ALLOWED_DRIFT_SECONDS = 300

    def __init__(self, mauth_auth, logger, mauth_base_url, mauth_api_version):
        """
        MAuthAuthenticator for authenticating requests (Base class)
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
        Authenticate the request
        :param request:
        """
        if self.authentication_present(request):
            if self.time_valid(request):
                if self.token_valid(request):
                    return self.signature_valid(request)
        return False

    def is_authentic(self, request):
        self.log_authentication_request(request)
        try:
            status = self.authenticate(request)
        except InauthenticError as exc:
            self.log_authentication_error(request, exc.message)
        return False

    def log_authentication_error(self, request, message):
        pass

    def log_authentication_request(self, request):
        pass

    def authentication_present(self, request):
        """
        Is the authentication header present (assuming request has a headers attribute) that
        can be treated like a dict
        :param request: Request like object
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
        :param request: Request like object
        :rtype: bool
        :return: success
        """
        if not settings.signature_info.match(request.headers.get(settings.x_mws_authentication)):
            raise InauthenticError("Token verification failed for {}. Misformatted "
                                   "Signature.".format(request.__class__.__name__))
        token, app_uuid, signature = settings.signature_info.match(
            request.headers.get(settings.x_mws_authentication)).groups()
        if not token == settings.mws_token:
            raise InauthenticError("Token verification failed for {}. "
                                   "Expected {}; token was {}".format(request.__class__.__name__,
                                                                      settings.mws_token, token))
        return True

    def signature_valid(self, request):
        """
        This should be implemented by the child classes
        :param request:
        :return:
        """
        raise NotImplemented

    def mauth_service_response_error(self, response):
        """
        Upstream MAuth Service error
        :param response:
        """
        message = "The mAuth service responded with {status}: {body}".format(status=response.status_code,
                                                                             body=response.content)
        self._logger.error(message)
        raise UnableToAuthenticateError(message, response)


class RemoteAuthenticator(MAuthAuthenticator):
    def __init__(self, mauth_auth, logger, mauth_base_url, mauth_api_version):
        super(RemoteAuthenticator, self).__init__(mauth_auth=mauth_auth, logger=logger,
                                                  mauth_base_url=mauth_base_url,
                                                  mauth_api_version=mauth_api_version)

    def signature_valid(self, request):
        """
        Is the signature valid?
        :param request: Request instance
        :type request: werkzeug.wrappers.BaseRequest
        """
        token, app_uuid, signature = settings.signature_info.match(
            request.headers.get(settings.x_mws_authentication)).groups()
        url = urljoin(self._mauth_base_url, "/mauth/{mauth_api_version}/" \
                                            "authentication_tickets.json".format(
            mauth_api_version=self._mauth_api_version))
        authentication_ticket = dict(verb=request.method,
                                     app_uuid=app_uuid,
                                     client_signature=signature,
                                     request_url=request.path,
                                     request_time=request.headers.get(settings.x_mws_time),
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
            self.mauth_service_response_error(response)
        # Strictly speaking, this is unreachable
        return False


class LocalAuthenticator(MAuthAuthenticator):
    def __init__(self, mauth_auth, logger, mauth_base_url, mauth_api_version):
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
        # original_request_uri = request.full_path
        # mws_time = request.headers.get(settings.x_mws_time)
        # mws_signature = request.headers.get(settings.x_mws_authentication)
        # craft an expected string-to-sign without doing any percent-encoding
        # expected_no_reencoding = object.string_to_sign(time: object.x_mws_time, app_uuid: object.signature_app_uuid)

        # do a simple percent reencoding variant of the path
        # object.attributes_for_signing[:request_url] = CGI.escape(original_request_uri.to_s)
        # expected_for_percent_reencoding = object.string_to_sign(time: object.x_mws_time,
        # app_uuid: object.signature_app_uuid)

        # do a moderately complex Euresource-style reencoding of the path
        # object.attributes_for_signing[:request_url] = CGI.escape(original_request_uri.to_s)
        # object.attributes_for_signing[:request_url].gsub!('%2F', '/') # ...and then 'simply'
        #  decode the %2F's back into /'s, just like Euresource kind of does!
        # expected_euresource_style_reencoding = object.string_to_sign(time: object.x_mws_time, app_uuid: object.signature_app_uuid)

        # reset the object original request_uri, just in case we need it again
        # object.attributes_for_signing[:request_url] = original_request_uri

        # extract the header
        token, app_uuid, signature = settings.signature_info.match(
            request.headers.get(settings.x_mws_authentication)).groups()

        expected = Signature.from_request(request=request)
        try:
            rsakey = RSA.importKey(self.secure_token_cacher.get(app_uuid=app_uuid))
            actual = Signature.from_signature(rsakey.decrypt(b64decode(signature)))
            if actual != expected:
                raise InauthenticError("Signature verification failed for {}".format(request.__class__.__name__))
        except Exception as exc:
            # TODO: work out what exceptions we will see here....
            raise InauthenticError("Public key decryption of signature "
                                   "failed!\n{}: {}".format(request.__class__.__name__,
                                                            exc.message))

            # TODO: time-invariant comparison instead of #== ?
            # unless expected_no_reencoding == actual || expected_euresource_style_reencoding == actual || expected_for_percent_reencoding == actual
            #   raise InauthenticError, "Signature verification failed for #{object.class}"
            # end
