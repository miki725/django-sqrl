# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import unittest
from collections import OrderedDict
from random import SystemRandom

import ed25519
import mock
import six

from ..crypto import HMAC, Ed25519, generate_randomness
from ..models import SQRLNut
from ..utils import Base64


TESTING_MODULE = 'sqrl.crypto'


class TestHMAC(unittest.TestCase):
    def setUp(self):
        super(TestHMAC, self).setUp()
        self.nut = SQRLNut(session_key='0123456789')
        self.data = OrderedDict([
            ('ver', '1'),
            ('tif', 0),
            ('mac', 'value'),
            ('qry', 'foo?nut=bar'),
        ])
        self.hmac = HMAC(self.nut, self.data)

    def test_init(self):
        hmac = HMAC(mock.sentinel.nut, mock.sentinel.data)

        self.assertEqual(hmac.nut, mock.sentinel.nut)
        self.assertEqual(hmac.data, mock.sentinel.data)

    def test_sign_data(self):
        signature = self.hmac.sign_data()

        self.assertIsInstance(signature, six.binary_type)
        self.assertEqual(len(signature), 20)
        self.assertEqual(
            signature,
            b'R\xfc\xb2\xbd\x12\x85\xae\xb0>\xdd\xed\x16P\xc2\x82\xae\x06\x0c\xc5\xd3'
        )

    @mock.patch(TESTING_MODULE + '.salted_hmac')
    def test_sign_data_mock(self, mock_salted_hmac):
        signature = self.hmac.sign_data()

        self.assertEqual(
            signature,
            mock_salted_hmac.return_value.digest.return_value
        )
        mock_salted_hmac.assert_called_once_with(
            self.nut.session_key,
            Base64.encode(b'ver=1\r\n'
                          b'tif=0\r\n'
                          b'qry=foo?nut=bar\r\n')
        )

    def test_sign_data_not_dict(self):
        with self.assertRaises(AssertionError):
            HMAC(mock.sentinel.nut, mock.sentinel.data).sign_data()

    @mock.patch.object(HMAC, 'sign_data')
    def test_is_signature_valid(self, mock_sign_data):
        mock_sign_data.return_value = 'foo_signature'

        self.assertTrue(self.hmac.is_signature_valid('foo_signature'))
        self.assertFalse(self.hmac.is_signature_valid('foo-signature'))

    def test_validation_loop(self):
        signature = self.hmac.sign_data()

        self.assertTrue(self.hmac.is_signature_valid(signature))
        self.assertFalse(self.hmac.is_signature_valid(b'a' + signature[:-1]))


class TestEd25519(unittest.TestCase):
    def setUp(self):
        super(TestEd25519, self).setUp()
        self.signing_key = (b'\xbbH\xdfx\xed\xc5\xdbR\x94\xe4\xff\xa6~5\xbb\xbd\xf2\x16&'
                            b'\xfc\x89\x8a\xc8\\\\\xeb\xea\x91Db~Hm+b\x88\xf2\x10\xfb:H'
                            b'\xe4\xfb0\x00\r\xe7n|\xa64\x05m@\xc8\xef"\x07k{O\xf0\xff%')
        self.verifying_key = (b'm+b\x88\xf2\x10\xfb:H\xe4\xfb0\x00\r\xe7n|\xa64\x05m@'
                              b'\xc8\xef"\x07k{O\xf0\xff%')
        self.data = b'data'
        self.sig = Ed25519(self.verifying_key, self.signing_key, self.data)

    def test_init(self):
        sig = Ed25519(mock.sentinel.pub_key,
                      mock.sentinel.priv_key,
                      mock.sentinel.msg)

        self.assertEqual(sig.public_key, mock.sentinel.pub_key)
        self.assertEqual(sig.private_key, mock.sentinel.priv_key)
        self.assertEqual(sig.msg, mock.sentinel.msg)

    def test_sign_data(self):
        signature = self.sig.sign_data()

        self.assertIsInstance(signature, six.binary_type)
        self.assertEqual(len(signature), 64)
        self.assertEqual(
            signature,
            b'\xac\xe0\x81\xc4\xd5\x7f\xd4\xe3\xc1\x03>\x0f\x90\xb5\x9eG<\xe0\xd41'
            b'\x1cZ\xd7\x15F\xba\xdeS/\xfa\xbbL\x9bh\x8dn;\xcfP\xb1\x16\x14&d\xde'
            b'\x97\x145\x90N[\xb9\xfc\x8e\x8a\x9e\xd2=\xad\x84\xcd\xf1\x93\x06'
        )

    @mock.patch('ed25519.SigningKey')
    def test_sign_data_mock(self, mock_signing_key):
        signature = self.sig.sign_data()

        self.assertEqual(signature, mock_signing_key.return_value.sign.return_value)
        mock_signing_key.assert_called_once_with(self.sig.private_key)
        mock_signing_key.return_value.sign.assert_called_once_with(self.sig.msg)

    def test_is_signature_valid(self):
        signature = self.sig.sign_data()

        self.assertTrue(self.sig.is_signature_valid(signature))
        self.assertFalse(self.sig.is_signature_valid(b'a' + signature[:-1]))

    @mock.patch('ed25519.VerifyingKey')
    def test_is_signature_mock(self, mock_verifying_key):
        is_valid = self.sig.is_signature_valid(mock.sentinel.signature)

        self.assertTrue(is_valid)
        mock_verifying_key.assert_called_once_with(self.sig.public_key)
        mock_verifying_key.return_value.verify.assert_called_once_with(
            mock.sentinel.signature, self.data
        )

    @mock.patch('ed25519.VerifyingKey')
    def test_is_signature_mock_assertion_error(self, mock_verifying_key):
        mock_verifying_key.return_value.verify.side_effect = AssertionError

        is_valid = self.sig.is_signature_valid(mock.sentinel.signature)

        self.assertFalse(is_valid)
        mock_verifying_key.assert_called_once_with(self.sig.public_key)
        mock_verifying_key.return_value.verify.assert_called_once_with(
            mock.sentinel.signature, self.data
        )

    @mock.patch('ed25519.VerifyingKey')
    def test_is_signature_mock_bas_signature_error(self, mock_verifying_key):
        mock_verifying_key.return_value.verify.side_effect = ed25519.BadSignatureError

        is_valid = self.sig.is_signature_valid(mock.sentinel.signature)

        self.assertFalse(is_valid)
        mock_verifying_key.assert_called_once_with(self.sig.public_key)
        mock_verifying_key.return_value.verify.assert_called_once_with(
            mock.sentinel.signature, self.data
        )


class TestUtils(unittest.TestCase):
    @mock.patch(TESTING_MODULE + '.bytearray', create=True)
    @mock.patch.object(Base64, 'encode')
    @mock.patch.object(SystemRandom, 'getrandbits')
    def test_generate_randomness_mock(self, mock_getrandbits, mock_encode, mock_bytearray):
        _mock_bytearray = mock.MagicMock()

        def _bytearray(a):
            list(a)
            return _mock_bytearray(a)

        mock_bytearray.side_effect = _bytearray

        randomness = generate_randomness()

        self.assertEqual(randomness, mock_encode.return_value)
        self.assertEqual(mock_getrandbits.call_count, 32)
        mock_getrandbits.assert_called_with(8)
        mock_encode.assert_called_once_with(_mock_bytearray.return_value)

    def test_generate_randomness(self):
        randomness = generate_randomness()

        self.assertIsInstance(randomness, six.text_type)
