# -*- coding: utf-8 -*-

__author__ = 'glow'

from six.moves.urllib.parse import urljoin, urlparse
from flask_mauth import settings

class Signature(object):
    """
    Represents a Signature for the purposes of comparison
    """

    def __init__(self, verb=None, url_path=None, body=None, app_uuid=None, seconds_since_epoch=None):
        self.verb = verb
        self.url_path = url_path
        self.body = body
        self.app_uuid = app_uuid
        self.seconds_since_epoch = seconds_since_epoch

    @classmethod
    def from_request(cls, request):
        """
        Build a Signature from a Request Object
        :param request: Request
        :type request: werkzeug.wrappers.BaseRequest
        :return: Signature object
        :rtype: Signature
        """
        token, app_uuid, signature = settings.signature_info. \
            match(request.headers.get(settings.x_mws_authentication)).groups()
        seconds_since_epoch = request.headers.get(settings.x_mws_time)

        return cls(verb=request.method,
                    url_path=urlparse(request.path).path,
                    body=request.data or '',
                    app_uuid=app_uuid,
                    seconds_since_epoch=seconds_since_epoch)

    @classmethod
    def from_signature(cls, signature):
        """
        Build a Signature from a signature string
        :param signature: signature string
        :type signature: str
        :return: Signature object
        :rtype: Signature
        """
        verb, url_path, body, app_uuid, seconds_since_epoch = signature.split('\n')
        return cls(verb,
                    url_path,
                    body,
                    app_uuid,
                    seconds_since_epoch)

    def __eq__(self, other):
        """
        Compare Signature Objects
        :param other: Signature object
        :type other: Signature
        :return: if the objects match
        :rtype: bool
        """
        assert isinstance(other, (Signature,))
        if self.app_uuid.lower() == other.app_uuid.lower():
            if urlparse(self.url_path) == urlparse(other.url_path):
                if self.verb == other.verb:
                    if self.seconds_since_epoch == other.seconds_since_epoch:
                        return True
        return False

    def __hash__(self):
        return '|'.join([self.app_uuid, self.url_path, self.seconds_since_epoch, self.verb, self.body])

