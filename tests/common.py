# -*- coding: utf-8 -*-

__author__ = 'glow'


import os
from hashlib import sha512

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


def get_hash(str_to_hash):
    return sha512(str_to_hash.encode('US-ASCII')).hexdigest()