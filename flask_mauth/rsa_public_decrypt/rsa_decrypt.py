# -*- coding: utf-8 -*-

__author__ = 'glow'

import base64

import six
from rsa import PublicKey, common, core, transform


class RSAPublicKey(PublicKey):

    def public_decrypt(self, message):
        """
        Decrypt a String encrypted with a private key, returns the hash
        :param message: encrypted message
        :return:
        """
        # base64 decode
        decoded = base64.b64decode(six.b(message))
        # transform the decoded message to int
        encrypted = transform.bytes2int(decoded)
        """:type : int"""
        payload = core.decrypt_int(encrypted, self.e, self.n)
        """:type : int"""
        padded = transform.int2bytes(payload, common.byte_size(self.n))
        """:type : str"""
        return padded

    def unpad_message(self, padded):
        """
        Removes the padding from the string
        :param padded: padded string
        :rtype: str
        """
        return padded[padded.index(b'\x00', 2) + 1:]