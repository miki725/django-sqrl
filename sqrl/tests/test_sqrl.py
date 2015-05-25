# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import unittest

import mock

from sqrl.managers import SQRLNutManager

from ..sqrl import SQRLInitialization


TESTING_MODULE = 'sqrl.sqrl'


class TestSQRLInitialization(unittest.TestCase):
    def test_init(self):
        sqrl = SQRLInitialization(mock.sentinel.request, mock.sentinel.nut)

        self.assertEqual(sqrl.request, mock.sentinel.request)
        self.assertEqual(sqrl.nut, mock.sentinel.nut)

    def test_get_or_create_session_key_exists(self):
        m = mock.MagicMock()
        self.assertEqual(
            SQRLInitialization(m).get_or_create_session_key(),
            m.session.session_key
        )
        self.assertFalse(m.session.create.called)

    def test_get_or_create_session_key_create(self):
        m = mock.MagicMock()
        m.session.session_key = None

        self.assertEqual(
            SQRLInitialization(m).get_or_create_session_key(),
            m.session.session_key
        )
        m.session.create.assert_called_once_with()

    @mock.patch.object(SQRLInitialization, 'generate_nut_kwargs')
    @mock.patch.object(SQRLNutManager, 'replace_or_create')
    def test_nut(self, mock_replace_or_create, mock_generate_nut_kwargs):
        mock_generate_nut_kwargs.return_value = {
            'foo': 'bar'
        }

        sqrl = SQRLInitialization(None)

        self.assertEqual(sqrl.nut, mock_replace_or_create.return_value)
        mock_replace_or_create.assert_called_once_with(foo='bar')
        mock_generate_nut_kwargs.assert_called_once_with()

    def test_nut_setter(self):
        sqrl = SQRLInitialization(None)

        # sanity check
        self.assertFalse(hasattr(sqrl, '_nut'))

        sqrl.nut = mock.sentinel.nut

        self.assertTrue(hasattr(sqrl, '_nut'))
        self.assertEqual(sqrl._nut, mock.sentinel.nut)
        self.assertEqual(sqrl.nut, mock.sentinel.nut)

    @mock.patch.object(SQRLInitialization, 'get_or_create_session_key')
    @mock.patch(TESTING_MODULE + '.get_user_ip')
    @mock.patch(TESTING_MODULE + '.generate_randomness')
    def test_generate_nut_kwargs(self, mock_generate_randomness, mock_get_user_ip,
                                 mock_get_or_create_session_key):
        mock_generate_randomness.return_value = 'abc123'

        actual = SQRLInitialization(mock.sentinel.request).generate_nut_kwargs()

        self.assertDictEqual(
            actual, {
                'session_key': mock_get_or_create_session_key.return_value,
                'nonce': 'abc',
                'transaction_nonce': '123',
                'is_transaction_complete': False,
                'ip_address': mock_get_user_ip.return_value,
            }
        )
        mock_generate_randomness.assert_called_once_with(64)
        mock_get_user_ip.assert_called_once_with(mock.sentinel.request)

    @mock.patch(TESTING_MODULE + '.reverse')
    def test_get_sqrl_url(self, mock_reverse):
        actual = SQRLInitialization(None).get_sqrl_url()

        self.assertEqual(actual, mock_reverse.return_value)

    def test_get_sqrl_url_params(self):
        actual = SQRLInitialization(None, mock.MagicMock(nonce='foo&bar')).get_sqrl_url_params()

        self.assertEqual(actual, 'nut=foo%26bar')

    @mock.patch.object(SQRLInitialization, 'get_sqrl_url_params')
    @mock.patch.object(SQRLInitialization, 'get_sqrl_url')
    def test_url(self, mock_get_sqrl_url, mock_get_sqrl_url_params):
        mock_get_sqrl_url.return_value = '/sqrl/auth/'
        mock_get_sqrl_url_params.return_value = 'nut=nonce'

        actual = SQRLInitialization(None).url

        self.assertEqual(actual, '/sqrl/auth/?nut=nonce')

    @mock.patch.object(SQRLInitialization, 'url', new_callable=mock.PropertyMock)
    def test_sqrl_url(self, mock_url):
        mock_url.return_value = '/sqrl/auth/?nut=nonce'

        request = mock.MagicMock()
        request.is_secure.return_value = True
        request.get_host.return_value = 'example.com:8000'

        actual = SQRLInitialization(request).sqrl_url

        self.assertEqual(actual, 'sqrl://example.com:8000/sqrl/auth/?nut=nonce')
