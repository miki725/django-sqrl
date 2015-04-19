# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import re
from collections import OrderedDict

import six
from django import forms
from django.core.urlresolvers import Resolver404, resolve
from django.core.validators import URLValidator
from django.http import QueryDict

from .utils import Base64


class NextUrlField(forms.CharField):
    default_error_messages = {
        'invalid_url': 'Invalid next url.'
    }

    def to_python(self, value):
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
    default_error_messages = {
        'missing_next': 'Missing next query parameter.'
    }

    def to_python(self, value):
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
    schemes = ['sqrl', 'qrl']
    regex = re.compile(
        r'^(?:[a-z0-9\.\-]*)://'  # scheme is validated separately
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}(?<!-)\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/\|?]\S+)$', re.IGNORECASE
    )


class SQRLURLField(forms.URLField):
    default_validators = [SQRLURLValidator()]


class Base64Field(forms.CharField):
    default_error_messages = {
        'base64': 'Invalid value. Must be base64url encoded string.',
    }

    def to_python(self, value):
        value = super(Base64Field, self).to_python(value)
        if not value:
            return b''
        try:
            return Base64.decode(value)
        except ValueError:
            raise forms.ValidationError(self.error_messages['base64'])


class Base64CharField(Base64Field):
    default_error_messages = {
        'base64_ascii': 'Invalid value. Must be ascii base64url encoded string.',
    }

    def to_python(self, value):
        value = super(Base64CharField, self).to_python(value)
        if not value:
            return ''
        try:
            return value.decode('ascii')
        except UnicodeDecodeError:
            raise forms.ValidationError(self.error_messages['base64_ascii'])


class Base64PairsField(Base64CharField):
    default_error_messages = {
        'crlf': 'Invalid value. Must be multi-line string separated by CRLF.',
        'pairs': 'Invalid value. Must be multi-line string of pair of values.',
    }
    always_pairs = True

    def to_python(self, value):
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
    always_pairs = False


class TildeMultipleValuesField(forms.CharField):
    def to_python(self, value):
        value = super(TildeMultipleValuesField, self).to_python(value)
        if not value:
            return []
        return value.split('~')


class TildeMultipleValuesFieldChoiceField(TildeMultipleValuesField, forms.ChoiceField):
    def validate(self, value):
        for i in value:
            super(TildeMultipleValuesFieldChoiceField, self).validate(i)
