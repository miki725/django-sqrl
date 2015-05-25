# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import unittest

import mock

from ..managers import SQRLNutManager


class TestSQRLNutManager(unittest.TestCase):
    @mock.patch.object(SQRLNutManager, 'get_queryset')
    @mock.patch.object(SQRLNutManager, 'create')
    def test_replace_or_create(self, mock_create, mock_getqueryset):
        actual = SQRLNutManager().replace_or_create(
            session_key=mock.sentinel.session_key,
            nonce=mock.sentinel.nonce,
            transaction_nonce=mock.sentinel.transaction_nonce,
            is_transaction_complete=False,
            ip_address=mock.sentinel.ip_address,
        )

        self.assertEqual(actual, mock_create.return_value)
        mock_getqueryset.return_value.filter.assert_called_once_with(
            session_key=mock.sentinel.session_key
        )
        mock_getqueryset.return_value.filter.return_value.delete.assert_called_once_with()
        mock_create.assert_called_once_with(
            session_key=mock.sentinel.session_key,
            nonce=mock.sentinel.nonce,
            transaction_nonce=mock.sentinel.transaction_nonce,
            is_transaction_complete=False,
            ip_address=mock.sentinel.ip_address,
        )
