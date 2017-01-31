# -*- coding: utf-8 -*-

import unittest
from hashlib import sha512

import six
from requests_mauth.rsa_sign import RSARawSigner

from flask_mauth.rsa_public_decrypt.rsa_decrypt import RSAPublicKey
from tests.common import load_key


class TestRSAPublicKey(unittest.TestCase):

    def test_round_trip(self):
        """We can encrypt a message with a priv key and decrypt with a public key"""
        string_to_sign = "Hello world"
        # we compare the hash, rather than the message itself....
        hashed = sha512(string_to_sign.encode('US-ASCII')).hexdigest()
        # load the public key
        pubkey = load_key()
        priv_key = load_key('priv')
        signer = RSARawSigner(private_key_data=priv_key)
        encrypted = signer.sign(string_to_sign)
        unsigner = RSAPublicKey.load_pkcs1(pubkey)
        padded = unsigner.public_decrypt(encrypted)
        actual = unsigner.unpad_message(padded)
        self.assertEqual(six.b(hashed), actual,
                         "Expected {}, got {}".format(hashed, actual))


if __name__ == '__main__':
    unittest.main()
