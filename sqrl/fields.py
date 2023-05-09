# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
from collections import OrderedDict

import six
from django import forms
from django.urls import Resolver404, resolve
from django.core.validators import URLValidator
from django.http import QueryDict

from .utils import Base64


class NextUrlField(forms.CharField):
    """
    Custom ``CharField`` which validates that a value is a valid next URL.

    It validates that by checking that the value can be resolved to a view
    hence guaranteeing that when redirected URL will not fail.
    """
    default_error_messages = {
        'invalid_url': 'Invalid next url.'
    }

    def to_python(self, value):
        """
        Validate that value is a valid URL for this project.
        """
        value = super(NextUrlField, self).to_python(value)

        if value in self.empty_values:
            return value

        parsed = six.moves.urllib.parse.urlparse(value)
        path = parsed.path

        try:
            resolve(path)
        except Resolver404:
            raise forms.ValidationError(self.error_messages['invalid_url'])
        else:
            return path


class ExtractedNextUrlField(NextUrlField):
    """
    Similar to :obj:`.NextUrlField` however this extracts next url from full encoded URL.
    """
    default_error_messages = {
        'missing_next': 'Missing next query parameter.'
    }

    def to_python(self, value):
        """
        Extract next url from full URL string and then use :obj:`.NextUrlField`
        to validate that value is valid URL.
        """
        value = forms.CharField.to_python(self, value)

        if value in self.empty_values:
            return value

        decoded = six.moves.urllib.parse.urlparse(
            six.moves.urllib.parse.unquote(value)
        )
        data = QueryDict(decoded.query)

        if 'next' not in data:
            raise forms.ValidationError(self.error_messages['missing_next'])

        return super(ExtractedNextUrlField, self).to_python(data['next'])


class SQRLURLValidator(URLValidator):
    """
    Custom URL validator which validates that a URL is a valid SQRL url.

    These are the differences with regular HTTP URLs:

    * scheme is either sqrl (secure) and qrl (non-secure)
    * ``:`` is a valid path separator which can be used to indicate
      which section of the SQRL should be used to generate
      public/provate keypair for the domain.
    """
    schemes = ['sqrl', 'qrl']


class SQRLURLField(forms.URLField):
    """
    SQRL URL field which uses :obj:`.SQRLURLValidator` for validation.
    """
    default_validators = [SQRLURLValidator()]


class Base64Field(forms.CharField):
    """
    Field which decodes base64 values using :meth:`.utils.Base64.decode`.
    """
    default_error_messages = {
        'base64': 'Invalid value. Must be base64url encoded string.',
    }

    def to_python(self, value):
        """
        Decodes base64 value and returns binary data.
        """
        value = super(Base64Field, self).to_python(value)
        if not value:
            return b''
        try:
            return Base64.decode(value)
        except (ValueError, TypeError):
            raise forms.ValidationError(self.error_messages['base64'])


class Base64CharField(Base64Field):
    """
    Similar to :obj:`.Base64Field` however this field normalizes to ``str`` (``unicode``) data.
    """
    default_error_messages = {
        'base64_ascii': 'Invalid value. Must be ascii base64url encoded string.',
    }

    def to_python(self, value):
        """
        Returns base64 decoded data as string.

        Uses :meth:`.Base64Field.to_python` to decode base64 value
        which returns binary data and then this method further
        decodes ascii data to return ``str`` (``unicode``) data.
        """
        value = super(Base64CharField, self).to_python(value)
        if not value:
            return ''
        try:
            return value.decode('ascii')
        except UnicodeDecodeError:
            raise forms.ValidationError(self.error_messages['base64_ascii'])


class Base64PairsField(Base64CharField):
    """
    Field which normalizes base64 encoded multistring key-value pairs to ``OrderedDict``.

    Attributes
    ----------
    always_pairs : bool
        Boolean which enforces that the value must always be keypairs.
        When ``False`` and the value is not a keypair, the value itself
        is returned.
    """
    default_error_messages = {
        'crlf': 'Invalid value. Must be multi-line string separated by CRLF.',
        'pairs': 'Invalid value. Must be multi-line string of pair of values.',
    }
    always_pairs = True

    def to_python(self, value):
        """
        Normalizes multiline base64 keypairs string to ``OrderedDict``.
        """
        value = super(Base64PairsField, self).to_python(value)
        if not value:
            return OrderedDict()

        if not value.endswith('\r\n'):
            if self.always_pairs:
                raise forms.ValidationError(self.error_messages['crlf'])
            else:
                return value

        try:
            return OrderedDict(
                line.split('=', 1) for line in filter(None, value.splitlines())
            )
        except ValueError:
            raise forms.ValidationError(self.error_messages['pairs'])


class Base64ConditionalPairsField(Base64PairsField):
    """
    Similar to :obj:`.Base64PairsField` but this field does not force
    the value to be keypairs.
    """
    always_pairs = False


class TildeMultipleValuesField(forms.CharField):
    """
    Field which returns tilde-separated list.
    """

    def to_python(self, value):
        """
        Normalizes to a Python list by splitting string by tilde (~) delimiter.
        """
        value = super(TildeMultipleValuesField, self).to_python(value)
        if not value:
            return []
        return value.split('~')


class TildeMultipleValuesFieldChoiceField(TildeMultipleValuesField, forms.ChoiceField):
    """
    Similar to :obj:`.TildeMultipleValuesField` however this field also validates
    each value to be a valid choice.
    """

    def validate(self, value):
        for i in value:
            super(TildeMultipleValuesFieldChoiceField, self).validate(i)
