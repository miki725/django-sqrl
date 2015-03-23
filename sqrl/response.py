# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import logging
from pprint import pformat

from django.conf import settings
from django.http import HttpResponse

from .exceptions import TIF
from .utils import Encoder, sign_data


log = logging.getLogger(__name__)


class SQRLHttpResponse(HttpResponse):
    def __init__(self, nut, data, *args, **kwargs):
        normalized_data = Encoder.normalize(self.sign_response(nut, data))
        content = self.construct_http_server_response(normalized_data)

        kwargs.setdefault('content_type', 'text/plain')

        super(SQRLHttpResponse, self).__init__(content, *args, **kwargs)

        self['Content-Length'] = len(self.content)

        self.add_debug_headers(normalized_data)

        log.debug('Response encoded data:\n{}'
                  ''.format(content))
        log.debug('Response data:\n{}'
                  ''.format(pformat(normalized_data)))
        log.debug('Response TIF breakdown:\n{}'
                  ''.format(pformat(TIF(int(data['tif'], 16)).breakdown())))

    def sign_response(self, nut, data):
        if not nut:
            return data

        data['mac'] = sign_data(data, nut)

        return data

    def construct_http_server_response(self, data):
        return Encoder.base64_dumps(data)

    def add_debug_headers(self, normalized_data):
        if settings.DEBUG:
            for k, v in normalized_data.items():
                self['SQRL-{}'.format(k)] = v
