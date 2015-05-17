# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import logging
from pprint import pformat

from django.conf import settings
from django.http import HttpResponse

from .crypto import HMAC
from .exceptions import TIF
from .utils import Encoder


log = logging.getLogger(__name__)


class SQRLHttpResponse(HttpResponse):
    """
    Custom ``HTTPResponse`` class used to return SQRL-formatted response.

    The response is automatically signed, normalized and encoded
    as per SQRL specification.

    This view also adds a couple of DEBUG logs for easier SQRL debugging
    and also returns all SQRL data back as ``X-SQRL-*`` headers.

    Parameters
    ----------
    nut : SQRLNut
        Nut which will be used to sign the response data.
    data : OrderedDict
        Data to be returned back to the user.
    """

    def __init__(self, nut, data, *args, **kwargs):
        normalized_data = Encoder.normalize(self.sign_response(nut, data))
        content = Encoder.base64_dumps(normalized_data)

        kwargs.setdefault('content_type', 'text/plain')

        super(SQRLHttpResponse, self).__init__(content, *args, **kwargs)

        self['Content-Length'] = len(self.content)

        if settings.DEBUG:
            for k, v in normalized_data.items():
                self['X-SQRL-{}'.format(k)] = v

            log.debug('Response encoded data:\n{}'
                      ''.format(content))
            log.debug('Response data:\n{}'
                      ''.format(pformat(normalized_data)))
            log.debug('Response TIF breakdown:\n{}'
                      ''.format(pformat(TIF(int(data['tif'], 16)).breakdown())))

    def sign_response(self, nut, data):
        """
        When nut is present, this method signs the data by adding ``mac`` key.

        For signing :meth:`.crypto.HMAC.sign_data` is used.
        """
        if not nut:
            return data

        data['mac'] = HMAC(nut, data).sign_data()

        return data
