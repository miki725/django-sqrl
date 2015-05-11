# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
from collections import OrderedDict
from random import SystemRandom

import ed25519
from django.utils.crypto import constant_time_compare, salted_hmac

from .utils import Base64, Encoder


random = SystemRandom()


class HMAC(object):
    def __init__(self, nut, data):
        self.nut = nut
        self.data = data

    def sign_data(self):
        assert isinstance(self.data, OrderedDict)

        encoded = Encoder.base64_dumps(OrderedDict(
            (k, v) for k, v in self.data.items()
            if k != 'mac'
        ))
        signature = salted_hmac(self.nut.session_key, encoded).digest()

        return signature

    def is_signature_valid(self, other_signature):
        expected_signature = self.sign_data()
        return constant_time_compare(expected_signature, other_signature)


class Ed25519(object):
    def __init__(self, key, msg):
        self.key = key
        self.msg = msg

    def is_signature_valid(self, other_signature):
        try:
            vk = ed25519.VerifyingKey(self.key)
            vk.verify(other_signature, self.msg)
        except (AssertionError, ed25519.BadSignatureError):
            return False
        else:
            return True

    def sign_data(self):
        sk = ed25519.SigningKey(self.key)
        return sk.sign(self.msg)


def generate_randomness(bytes=32):
    return Base64.encode(bytearray(random.getrandbits(8) for i in range(bytes)))
