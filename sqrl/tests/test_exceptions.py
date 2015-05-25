# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import unittest

import mock

from ..exceptions import TIF, TIFException


TESTING_MODULE = 'sqrl.exceptions'


class TestTIF(unittest.TestCase):
    def test_as_hex_string(self):
        self.assertEqual(TIF(0x1).as_hex_string(), '1')
        self.assertEqual(TIF(0x4).as_hex_string(), '4')
        self.assertEqual(TIF(0x88).as_hex_string(), '88')
        self.assertEqual(TIF(0x84).as_hex_string(), '84')

    def test_breakdown(self):
        self.assertDictEqual(TIF(0x34).breakdown(), {
            'id_match': False,
            'previous_id_match': False,
            'ip_match': True,
            'sqrl_disabled': False,
            'not_supported': True,
            'transient_failure': True,
            'command_failed': False,
            'client_failure': False,
            'bad_id_association': False,
        })

    def test_update(self):
        tif = TIF(0x3).update(TIF(0x40))

        self.assertIsInstance(tif, TIF)
        self.assertEqual(tif, 0x43)

    def test_properties(self):
        self.assertTrue(TIF(TIF.ID_MATCH).is_id_match)
        self.assertTrue(TIF(TIF.PREVIOUS_ID_MATCH).is_previous_id_match)
        self.assertTrue(TIF(TIF.IP_MATCH).is_ip_match)
        self.assertTrue(TIF(TIF.SQRL_DISABLED).is_sqrl_disabled)
        self.assertTrue(TIF(TIF.NOT_SUPPORTED).is_not_supported)
        self.assertTrue(TIF(TIF.TRANSIENT_FAILURE).is_transient_failure)
        self.assertTrue(TIF(TIF.COMMAND_FAILED).is_command_failed)
        self.assertTrue(TIF(TIF.CLIENT_FAILURE).is_client_failure)
        self.assertTrue(TIF(TIF.BAD_ID_ASSOCIATION).is_bad_id_association)


class TestTIFException(unittest.TestCase):
    @mock.patch(TESTING_MODULE + '.TIF')
    def test_init(self, mock_tif):
        e = TIFException(mock.sentinel.tif)

        self.assertEqual(e.tif, mock_tif.return_value)
        mock_tif.assert_called_once_with(mock.sentinel.tif)
