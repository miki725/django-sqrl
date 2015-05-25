# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import unittest
from collections import OrderedDict

import mock
import qrcode
import six

from ..utils import Base64, Encoder, QRGenerator, get_user_ip


TESTING_MODULE = 'sqrl.utils'


class TestBase64(unittest.TestCase):
    def test_encode(self):
        value = Base64.encode(b'hello')

        # normal base64 is aGVsbG8= however = should be missing
        self.assertEqual(value, 'aGVsbG8')
        self.assertIsInstance(value, six.text_type)

    def test_encode_not_binary(self):
        with self.assertRaises(AssertionError):
            Base64.encode('hello')

    def test_decode(self):
        value = Base64.decode('aGVsbG8')

        # normal base64 is aGVsbG8= however = should be missing
        self.assertEqual(value, b'hello')
        self.assertIsInstance(value, six.binary_type)

    def test_decode_not_unicode(self):
        with self.assertRaises(AssertionError):
            Base64.decode(b'aGVsbG8')


class TestEncode(unittest.TestCase):
    def test_base64_dumps(self):
        self.assertEqual(Encoder.base64_dumps(5), '5')
        self.assertEqual(Encoder.base64_dumps('hello'), 'hello')
        self.assertEqual(Encoder.base64_dumps(b'hello'), 'aGVsbG8')
        self.assertEqual(Encoder.base64_dumps([b'hello', 'hello']), 'aGVsbG8~hello')
        self.assertEqual(
            Encoder.base64_dumps(OrderedDict([('a', b'hello'), ('b', 'hello')])),
            'YT1hR1ZzYkc4DQpiPWhlbGxvDQo'
        )

    def test_dumps(self):
        self.assertEqual(Encoder.dumps(5), '5')
        self.assertEqual(Encoder.dumps('hello'), 'hello')
        self.assertEqual(Encoder.dumps(b'hello'), 'aGVsbG8')
        self.assertEqual(Encoder.dumps([b'hello', 'hello']), 'aGVsbG8~hello')
        self.assertEqual(Encoder.dumps(OrderedDict()), '')
        self.assertEqual(
            Encoder.dumps(OrderedDict([('a', b'hello'), ('b', 'hello')])),
            'a=aGVsbG8\r\nb=hello\r\n'
        )

    def test_normalize(self):
        self.assertEqual(Encoder.normalize(b'hello'), 'aGVsbG8')
        self.assertEqual(Encoder.normalize('hello'), 'hello')
        self.assertEqual(Encoder.normalize(5), '5')
        self.assertEqual(Encoder.normalize([b'hello', 'hello']), ['aGVsbG8', 'hello'])
        self.assertEqual(Encoder.normalize(OrderedDict()), '')
        self.assertEqual(
            Encoder.normalize(OrderedDict([('a', b'hello'), ('b', 'hello')])),
            OrderedDict([('a', 'aGVsbG8'), ('b', 'hello')])
        )


class TestQRGenerator(unittest.TestCase):
    def test_init(self):
        qr = QRGenerator(mock.sentinel.url)

        self.assertEqual(qr.url, mock.sentinel.url)

    @mock.patch(TESTING_MODULE + '.QRCode')
    def test__generate_image(self, mock_qrcode):
        actual = QRGenerator('sqrl://example.com/path?nut=foo')._generate_image()

        self.assertEqual(actual, mock_qrcode.return_value.make_image.return_value)
        mock_qrcode.assert_called_once_with(error_correction=qrcode.ERROR_CORRECT_L)
        mock_qrcode.return_value.add_data.assert_called_once_with(
            'sqrl://example.com/path?nut=foo'
        )
        mock_qrcode.return_value.make_image.assert_called_once_with()

    @mock.patch.object(QRGenerator, '_generate_image')
    @mock.patch(TESTING_MODULE + '.ContentFile')
    def test_generate_image(self, mock_content_file, mock_generate_image):
        actual = QRGenerator('sqrl://example.com/path?nut=foo').generate_image()

        self.assertEqual(actual, mock_content_file.return_value.read.return_value)
        mock_generate_image.assert_called_once_with()
        mock_content_file.assert_called_once_with(b'', name='qr.png')
        mock_generate_image.return_value.save.assert_called_once_with(
            mock_content_file.return_value, 'png'
        )
        mock_content_file.return_value.seek.assert_called_once_with(0)


class TestUtils(unittest.TestCase):
    def test_get_user_ip(self):
        request = mock.MagicMock(META={'REMOTE_ADDR': mock.sentinel.ip})

        self.assertEqual(get_user_ip(request), mock.sentinel.ip)

    def test_get_user_ip_proxy(self):
        request = mock.MagicMock(META={'HTTP_X_REAL_IP': mock.sentinel.ip})

        self.assertEqual(get_user_ip(request), mock.sentinel.ip)
