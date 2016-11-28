# -*- coding: utf-8 -*-

__author__ = 'glow'


class InauthenticError(Exception):
    # used to indicate that an object was expected to be validly signed but its signature does not
    # match its contents, and so is inauthentic.
    pass


class UnableToAuthenticateError(Exception):
    # the response from the MAuth service encountered when attempting to retrieve mauth
    def __init__(self, message, response=None):
        super(UnableToAuthenticateError, self).__init__(message)
        self.response = response


class UnableToSignError(Exception):
    # required information for signing was missing
    pass
