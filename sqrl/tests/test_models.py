# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import unittest

import mock
import six

from ..managers import SQRLNutManager
from ..models import SQRLNut


TESTING_MODULE = 'sqrl.models'


class TestSQRLNut(unittest.TestCase):
    def test_objects(self):
        self.assertIsInstance(SQRLNut.objects, SQRLNutManager)

    def test_str(self):
        self.assertEqual(
            six.text_type(SQRLNut(nonce='nonce')),
            'nonce'
        )

    @mock.patch(TESTING_MODULE + '.generate_randomness')
    @mock.patch.object(SQRLNut, 'delete')
    @mock.patch.object(SQRLNut, 'save')
    def test_renew(self, mock_save, mock_delete, mock_generate_randomness):
        nut = SQRLNut(nonce='nonce')

        self.assertIsNone(nut.renew())
        self.assertEqual(nut.nonce, mock_generate_randomness.return_value)
        mock_save.assert_called_once_with()
        mock_generate_randomness.assert_called_once_with()
