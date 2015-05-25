# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import unittest
from collections import OrderedDict

import mock
import six
from django import forms
from django.core.urlresolvers import Resolver404

from ..fields import (
    Base64CharField,
    Base64ConditionalPairsField,
    Base64Field,
    Base64PairsField,
    ExtractedNextUrlField,
    NextUrlField,
    SQRLURLField,
    SQRLURLValidator,
    TildeMultipleValuesField,
    TildeMultipleValuesFieldChoiceField,
)
from ..utils import Base64


TESTING_MODULE = 'sqrl.fields'


class TestNextUrlField(unittest.TestCase):
    def test_to_python_empty(self):
        self.assertEqual(NextUrlField().to_python(None), '')

    @mock.patch(TESTING_MODULE + '.resolve')
    def test_to_python_valid(self, mock_resolve):
        value = 'http://example.com/path/here/?querystring=here'
        self.assertEqual(NextUrlField().to_python(value), '/path/here/')

    @mock.patch(TESTING_MODULE + '.resolve')
    def test_to_python_invalid(self, mock_resolve):
        mock_resolve.side_effect = Resolver404
        value = 'http://example.com/path/here/?querystring=here'

        with self.assertRaises(forms.ValidationError):
            NextUrlField().to_python(value)


class TestExtractedNextUrlField(unittest.TestCase):
    def test_to_python_empty(self):
        self.assertEqual(ExtractedNextUrlField().to_python(None), '')

    def test_to_python_next_not_present(self):
        value = 'http://example.com/path/here/?querystring=here'

        with self.assertRaises(forms.ValidationError):
            ExtractedNextUrlField().to_python(value)

    @mock.patch(TESTING_MODULE + '.resolve')
    def test_to_python(self, mock_resolve):
        value = 'http://example.com/path/here/?next=/next/here/'

        self.assertEqual(
            ExtractedNextUrlField().to_python(value),
            '/next/here/'
        )


class TestSQRLURLValidator(unittest.TestCase):
    def test_valid(self):
        self.assertIsNone(
            SQRLURLValidator()('qrl://example.com:8000/sqrl/?nut=hello')
        )
        self.assertIsNone(
            SQRLURLValidator()('sqrl://example.com:8000/sqrl/?nut=hello')
        )

    def test_invalid(self):
        with self.assertRaises(forms.ValidationError):
            SQRLURLValidator()('http://example.com:Base64PairsField8000/sqrl/?nut=hello')


class TestSQRLURLField(unittest.TestCase):
    def test_default_validators(self):
        validator_types = list(map(type, SQRLURLField.default_validators))
        self.assertIn(SQRLURLValidator, validator_types)


class TestBase64Field(unittest.TestCase):
    def test_empty_value(self):
        value = Base64Field().to_python(None)

        self.assertEqual(value, b'')
        self.assertIsInstance(value, six.binary_type)

    def test_value(self):
        value = Base64Field().to_python('aGVsbG8')

        self.assertEqual(value, b'hello')
        self.assertIsInstance(value, six.binary_type)

    def test_value_invalid(self):
        with self.assertRaises(forms.ValidationError):
            Base64Field().to_python('hello')


class TestBase64CharField(unittest.TestCase):
    def test_empty_value(self):
        value = Base64CharField().to_python(None)

        self.assertEqual(value, '')
        self.assertIsInstance(value, six.text_type)

    def test_value(self):
        value = Base64CharField().to_python('aGVsbG8')

        self.assertEqual(value, 'hello')
        self.assertIsInstance(value, six.text_type)

    def test_value_invalid(self):
        with self.assertRaises(forms.ValidationError):
            Base64CharField().to_python('z4A')


class TestBase64PairsField(unittest.TestCase):
    def test_to_python_empty(self):
        value = Base64PairsField().to_python(None)

        self.assertEqual(value, OrderedDict())

    def test_to_python(self):
        value = Base64.encode(
            b'ver=1\r\n'
            b'foo=bar\r\n'
        )

        value = Base64PairsField().to_python(value)

        self.assertEqual(value, OrderedDict([
            ('ver', '1'),
            ('foo', 'bar'),
        ]))

    def test_to_python_not_pars(self):
        value = Base64.encode(
            b'ver=1\r\n'
            b'foo\r\n'
        )

        with self.assertRaises(forms.ValidationError):
            Base64PairsField().to_python(value)

    def test_to_python_not_multiline(self):
        value = Base64.encode(
            b'ver=1'
        )

        with self.assertRaises(forms.ValidationError):
            Base64PairsField().to_python(value)


class TestBase64ConditionalPairsField(unittest.TestCase):
    def test_to_python_not_pars(self):
        value = Base64.encode(
            b'foo'
        )

        self.assertEqual(Base64ConditionalPairsField().to_python(value), 'foo')


class TestTildeMultipleValuesField(unittest.TestCase):
    def test_empty(self):
        self.assertListEqual(TildeMultipleValuesField().to_python(None), [])

    def test_to_python(self):
        self.assertListEqual(
            TildeMultipleValuesField().to_python('hello~world'),
            ['hello', 'world']
        )


class TestTildeMultipleValuesFieldChoiceField(unittest.TestCase):
    def test_valid(self):
        field = TildeMultipleValuesFieldChoiceField(choices=[
            ('hello', 'hello'),
            ('world', 'world'),
        ])

        self.assertListEqual(
            field.clean('hello~world'),
            ['hello', 'world']
        )

    def test_invalid(self):
        field = TildeMultipleValuesFieldChoiceField(choices=[
            ('hello', 'hello'),
        ])

        with self.assertRaises(forms.ValidationError):
            field.clean('hello~world')
