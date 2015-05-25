# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import unittest
from collections import OrderedDict

import mock
import six
from django.test.utils import override_settings

from ..crypto import HMAC
from ..response import SQRLHttpResponse
from ..utils import Encoder


TESTING_MODULE = 'sqrl.response'


class TestSQRLHttpResponse(unittest.TestCase):
    def setUp(self):
        super(TestSQRLHttpResponse, self).setUp()
        self.data = OrderedDict([
            ('ver', 1),
            ('nut', b'nonce'),
            ('tif', '8'),
            ('qry', '/sqrl/auth/?nut=nonce'),
            ('sfn', 'Test Server'),
        ])
        self.nut = mock.MagicMock(session_key='session')

    @override_settings(DEBUG=False)
    def test_response(self):
        response = SQRLHttpResponse(self.nut, self.data)

        expected_data = self.data.copy()
        expected_data['mac'] = HMAC(self.nut, self.data).sign_data()

        self.assertEqual(
            response.content,
            Encoder.base64_dumps(expected_data).encode('ascii')
        )
        self.assertEqual(response['Content-Length'], six.text_type(len(response.content)))
        self.assertEqual(response['Content-Type'], 'application/sqrl')

    @override_settings(DEBUG=False)
    def test_response_without_nut(self):
        response = SQRLHttpResponse(None, self.data)

        self.assertEqual(
            response.content,
            Encoder.base64_dumps(self.data).encode('ascii')
        )
        self.assertEqual(response['Content-Length'], six.text_type(len(response.content)))
        self.assertEqual(response['Content-Type'], 'application/sqrl')

    @override_settings(DEBUG=True)
    @mock.patch(TESTING_MODULE + '.log')
    def test_response_debug(self, mock_log):
        response = SQRLHttpResponse(self.nut, self.data)

        self.assertEqual(response['X-SQRL-ver'], '1')
        self.assertEqual(response['X-SQRL-nut'], 'bm9uY2U')
        self.assertEqual(response['X-SQRL-tif'], '8')
        self.assertEqual(response['X-SQRL-qry'], '/sqrl/auth/?nut=nonce')
        self.assertEqual(response['X-SQRL-sfn'], 'Test Server')
        self.assertIn('X-SQRL-mac', response)
