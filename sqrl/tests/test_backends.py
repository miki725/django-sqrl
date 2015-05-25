# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import unittest

import mock
from django.contrib.auth.backends import ModelBackend

from ..backends import SQRLModelBackend
from ..models import SQRLIdentity


class TestSQRLModelBackend(unittest.TestCase):
    @mock.patch.object(ModelBackend, 'authenticate')
    def test_authenticate_no_user(self, mock_authenticate):
        mock_authenticate.return_value = None

        self.assertIsNone(SQRLModelBackend().authenticate(
            username='user',
            password='password'
        ))

    @mock.patch.object(ModelBackend, 'authenticate')
    def test_authenticate_no_sqrl_identity(self, mock_authenticate):
        class UserMock(mock.MagicMock):
            @property
            def sqrl_identity(self):
                raise SQRLIdentity.DoesNotExist

        user = UserMock()
        mock_authenticate.return_value = user

        self.assertEqual(SQRLModelBackend().authenticate(
            username='user',
            password='password'
        ), user)

    @mock.patch.object(ModelBackend, 'authenticate')
    def test_authenticate_disabled(self, mock_authenticate):
        user = mock.MagicMock()
        user.sqrl_identity.is_only_sqrl = True
        user.sqrl_identity.is_enabled = True
        mock_authenticate.return_value = user

        self.assertIsNone(SQRLModelBackend().authenticate(
            username='user',
            password='password'
        ))

    @mock.patch.object(ModelBackend, 'authenticate')
    def test_authenticate_enabled(self, mock_authenticate):
        user = mock.MagicMock()
        user.sqrl_identity.is_only_sqrl = False
        user.sqrl_identity.is_enabled = True
        mock_authenticate.return_value = user

        self.assertEqual(SQRLModelBackend().authenticate(
            username='user',
            password='password'
        ), user)
