# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections import OrderedDict

import six
from django.core.files.base import ContentFile
from qrcode import ERROR_CORRECT_L, QRCode


class Base64(object):
    """
    Helper class for base64 encoding/decoding
    """

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
    """
    Helper class for encoding/decoding SQRL response data.
    """

    @classmethod
    def base64_dumps(cls, data):
        """
        Dumps given data into a single Base64 string.

        Practically this is the same as :meth:`dumps` except :meth:`dumps`
        can return multiline string for ``dict``. This method normalizes that
        further by converting that multiline string to a single base64 encoded value.

        Returns
        -------
        binary
            Base64 encoded binary data of input ``data``
        """
        if data and isinstance(data, dict):
            return Base64.encode(cls.dumps(data).encode('ascii'))
        return cls.dumps(data)

    @classmethod
    def dumps(cls, data):
        """
        Recursively dumps given data to SQRL response format.

        Before data is dumped out, it is normalized by using :meth:`.normalize`.

        This dumps each data type as follows:

        :``dict``: returns an ``\\r\\n`` multiline string. Each line is for a single key-pair
                   of format ``<key>=<dumped value>``.
        :``list``: tilde (``~``) joined dumped list of values
        :other: no operation
        """
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
        """
        Recursively normalize data for encoding.

        This encodes each data type as follows:

        :``dict``: returns an ``OrderedDict`` where all values are recursively normalized.
                   Empty dict is normalized to empty string
        :``list``: each value is recursively normalized
        :``binary``: Base64 encode data
        :``str``: no operation
        :other: data is casted to string using ``__str__`` (or ``__unicode__``)
        """
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
    """
    Helper class for generating a QR image for the given SQRL url.

    Parameters
    ----------
    url : str
        URL for which to generate QR image
    """

    def __init__(self, url):
        self.url = url

    def _generate_image(self):
        qr = QRCode(error_correction=ERROR_CORRECT_L)
        qr.add_data(self.url)
        return qr.make_image()

    def generate_image(self):
        """
        Generate QR image and get its binary data.

        Returns
        -------
        bytes
            Binary data of the png image file which can directly be returned to the user
        """
        img = self._generate_image(self.url)
        f = ContentFile(b'', name='qr.png')
        img.save(f, 'png')
        f.seek(0)
        return f.read()


def get_user_ip(request):
    """
    Utility function for getting user's IP from request address.

    This either returns the IP address from the ``request.REMOTE_ADDR``
    or ``request.META'HTTP_X_REAL_IP']`` when request might of
    been reverse proxied.
    """
    return (
        request.META.get('HTTP_X_REAL_IP')
        or request.META['REMOTE_ADDR']
    )
