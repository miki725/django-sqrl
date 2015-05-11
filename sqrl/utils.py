# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections import OrderedDict

import six
from django.core.files.base import ContentFile
from qrcode import ERROR_CORRECT_L, QRCode


class Base64(object):
    @classmethod
    def encode(cls, s):
        """
        Encode binary string as base64. Remaining "=" characters are removed.

        Parameters
        ----------
        s: bytes
            Bytes string to be encoded as base64
        """
        return urlsafe_b64encode(s).decode('ascii').rstrip('=')

    @classmethod
    def decode(cls, s):
        """
        Decode unicode string from base64 where remaining "=" characters were stripped.

        Parameters
        ----------
        s: str
            Unicode string to be decoded from base64
        """
        return urlsafe_b64decode((s + '=' * (4 - len(s) % 4)).encode('ascii'))


class Encoder(object):
    @classmethod
    def base64_dumps(cls, data):
        if data and isinstance(data, dict):
            return Base64.encode(cls.dumps(data).encode('ascii'))
        return cls.dumps(data)

    @classmethod
    def dumps(cls, data):
        data = cls.normalize(data)

        if isinstance(data, dict):
            if data:
                return '\r\n'.join(
                    '{}={}'.format(k, cls.dumps(v))
                    for k, v in data.items()
                ) + '\r\n'
            else:
                return ''
        elif isinstance(data, (list, tuple)):
            return '~'.join(cls.dumps(i) for i in data)
        else:
            return data

    @classmethod
    def normalize(cls, data):
        if isinstance(data, dict):
            if data:
                return OrderedDict((
                    (k, cls.normalize(v))
                    for k, v in data.items()
                ))
            else:
                return ''
        elif isinstance(data, (list, tuple)):
            return [cls.dumps(i) for i in data]
        elif isinstance(data, six.binary_type):
            return Base64.encode(data)
        elif isinstance(data, six.text_type):
            return data
        else:
            return six.text_type(data)


class QRGenerator(object):
    def _generate_image(self, url):
        qr = QRCode(error_correction=ERROR_CORRECT_L)
        qr.add_data(url)
        return qr.make_image()

    def generate_image(self, url):
        img = self._generate_image(url)
        f = ContentFile(b'', name='qr.png')
        img.save(f, 'png')
        f.seek(0)
        return f.read()


def get_user_ip(request):
    return (
        request.META.get('HTTP_X_REAL_IP')
        or request.META['REMOTE_ADDR']
    )
