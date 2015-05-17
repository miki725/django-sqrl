# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
from collections import OrderedDict
from random import SystemRandom

import ed25519
from django.utils.crypto import constant_time_compare, salted_hmac

from .utils import Base64, Encoder


random = SystemRandom()


class HMAC(object):
    """
    Utility class for generating and verifying HMAC signatures.

    This class relies on Django's built in :func:`salted_hmac`
    to compute actual HMAC values by using ``SECRET_KEY`` as key.

    Parameters
    ----------
    nut : SQRLNut
        Nut from which necessary data is extracted to add a salt value
        to the HMAC input data.
        Currently only :attr:`.models.SQRLNut.session_key` is used.
    data : OrderedDict
        Dict for which to either compute or validate HMAC signature.
    """

    def __init__(self, nut, data):
        self.nut = nut
        self.data = data

    def sign_data(self):
        """
        Generate HMAC signature for the provided data.

        Note
        ----
        ``max`` key is ignored in the input data if that key is present.

        Returns
        -------
        bytes
            Binary signature of the data
        """
        assert isinstance(self.data, OrderedDict)

        encoded = Encoder.base64_dumps(OrderedDict(
            (k, v) for k, v in self.data.items()
            if k != 'mac'
        ))
        signature = salted_hmac(self.nut.session_key, encoded).digest()

        return signature

    def is_signature_valid(self, other_signature):
        """
        Check if the ``other_signature`` is a valid signature for the
        provided data and the nut.

        Returns
        -------
        bool
            Boolean indicating whether validation has succeeded.
        """
        expected_signature = self.sign_data()
        return constant_time_compare(expected_signature, other_signature)


class Ed25519(object):
    """
    Utility class for signing and verifying ed25519 signatures.

    More information about ed25519 can be found at `<http://ed25519.cr.yp.to/>`_.

    Parameters
    ----------
    key : bytes
        Key for generating signature.
    msg : bytes
        Binary data for which to generate the signature.
    """

    def __init__(self, key, msg):
        self.key = key
        self.msg = msg

    def is_signature_valid(self, other_signature):
        """
        Check if ``other_signature`` is a valid signature for the provided message.

        Returns
        -------
        bool
            Boolean indicating whether validation has succeeded.
        """
        try:
            vk = ed25519.VerifyingKey(self.key)
            vk.verify(other_signature, self.msg)
        except (AssertionError, ed25519.BadSignatureError):
            return False
        else:
            return True

    def sign_data(self):
        """
        Generate ed25519 signature for the provided data.

        Returns
        -------
        bytes
            ed25519 signature
        """
        sk = ed25519.SigningKey(self.key)
        return sk.sign(self.msg)


def generate_randomness(bytes=32):
    """
    Generate random sample of specified size ``bytes``.

    Parameters
    ----------
    bytes : int, optional
        Number of bytes to generate random sample

    Returns
    -------
    str
        :meth:`.Base64.encode` encoded random sample
    """
    return Base64.encode(bytearray(random.getrandbits(8) for i in range(bytes)))
